use std::path::Path;
use std::time::{Duration, Instant};

use rampage_api::{DebuggerRequest, MAX_DEBUGGER_REQUEST_BYTES, query_debugger};
use serde_json::{Value, json};

fn token() -> Value {
    json!({"backend":"lldb-sb", "session_id":"controlled-test", "process_unique_id":7,
           "stop_id":3, "target_index":0})
}

fn describe() -> DebuggerRequest {
    DebuggerRequest::from_json(r#"{"version":1,"operation":"describe_session"}"#).unwrap()
}

fn resolve() -> Value {
    json!({"version":1,"operation":"resolve_module_address","expected_token":token(),
        "module_uuid":"01234567-89ab-cdef-0123-456789abcdef","file_address":"0x100000004"})
}

#[test]
fn module_resolution_requires_bounded_sdk_uuid_address_and_explicit_token() {
    for uuid in [
        "01234567-89AB-CDEF-0123-456789ABCDEF",
        "0123456789abcdef0123456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef-01234567",
        "0123456789abcdef0123456789abcdef01234567",
    ] {
        for address in [json!(0), json!(u64::MAX - 1), json!("0x100000004")] {
            let mut value = resolve();
            value["module_uuid"] = json!(uuid);
            value["file_address"] = address;
            let request = DebuggerRequest::from_json(&value.to_string()).unwrap();
            assert_eq!(request.operation(), "resolve_module_address");
            assert_eq!(serde_json::to_value(request).unwrap(), value);
        }
    }
    for (field, value) in [
        ("module_uuid", json!("fixture")),
        ("module_uuid", json!("0")),
        ("module_uuid", json!("ab-cd")),
        ("module_uuid", json!("a".repeat(129))),
        ("module_uuid", json!("é".repeat(32))),
        ("module_uuid", Value::Null),
        ("file_address", json!(u64::MAX)),
        ("file_address", json!("0x10000000000000000")),
        ("file_address", json!(-1)),
        ("file_address", json!(true)),
        ("file_address", Value::Null),
        ("expected_token", Value::Null),
        ("response_budget", Value::Null),
        ("response_budget", json!(1023)),
        ("response_budget", json!(262145)),
        ("module_id", json!(0)),
        ("path", json!("/must/not/open")),
        ("thread_id", json!(1)),
    ] {
        let mut invalid = resolve();
        invalid[field] = value;
        assert!(DebuggerRequest::from_json(&invalid.to_string()).is_err(), "{invalid}");
    }
    for field in ["module_uuid", "file_address", "expected_token"] {
        let mut invalid = resolve();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(DebuggerRequest::from_json(&invalid.to_string()).is_err());
    }
    let duplicate = resolve().to_string().replacen("\"file_address\":", "\"file_address\":0,\"file_address\":", 1);
    assert!(DebuggerRequest::from_json(&duplicate).is_err());
    let exact = format!("{}{}", resolve(), " ".repeat(MAX_DEBUGGER_REQUEST_BYTES - resolve().to_string().len()));
    assert!(DebuggerRequest::from_json(&exact).is_ok());
    assert!(DebuggerRequest::from_json(&format!("{exact}é")).is_err());
}

#[test]
fn typed_resolution_schema_requires_uuid_file_address_and_stop_token() {
    let schema = serde_json::to_value(schemars::schema_for!(DebuggerRequest)).unwrap();
    let variant = schema["oneOf"]
        .as_array()
        .or_else(|| schema["anyOf"].as_array())
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["operation"].to_string().contains("resolve_module_address"))
        .unwrap();
    assert_eq!(variant["additionalProperties"], false);
    let required = variant["required"].as_array().unwrap();
    for field in ["version", "operation", "expected_token", "module_uuid", "file_address"] {
        assert!(required.contains(&json!(field)));
    }
    assert_eq!(variant["properties"]["module_uuid"]["maxLength"], 149);
    assert!(variant["properties"].get("module_id").is_none());
    assert!(variant["properties"].get("path").is_none());
}

#[test]
fn requests_refuse_commands_unknown_duplicate_and_out_of_range_fields() {
    let bad = [
        r#"{"version":1,"operation":"continue"}"#.to_owned(),
        r#"{"version":1,"operation":"describe_session","command":"expression 1"}"#.to_owned(),
        r#"{"version":1,"operation":"describe_session","version":1}"#.to_owned(),
        r#"{"version":1,"operation":"describe_session","operation":"describe_session"}"#.to_owned(),
        r#"{"version":1,"operation":"describe_session","expected_token":null}"#.to_owned(),
        r#"{"version":1,"operation":"describe_session","response_budget":null}"#.to_owned(),
        r#"{"version":2,"operation":"describe_session"}"#.to_owned(),
        r#"{"version":1,"operation":"list_modules"}"#.to_owned(),
        format!("{} ", " ".repeat(MAX_DEBUGGER_REQUEST_BYTES)),
    ];
    for text in bad {
        assert!(DebuggerRequest::from_json(&text).is_err(), "{text}");
    }
    let mut request = json!({"version":1, "operation":"read_memory", "expected_token":token(),
                             "address":"0x1000", "size":4, "permissions":"r--"});
    assert!(DebuggerRequest::from_json(&request.to_string()).is_ok());
    for (field, value) in [
        ("address", json!("main")),
        ("address", json!(u64::MAX)),
        ("size", json!(0)),
        ("size", json!(65537)),
        ("permissions", json!("r?x")),
        ("thread_id", json!(0)),
        ("response_budget", json!(262145)),
    ] {
        let mut invalid = request.clone();
        invalid[field] = value;
        assert!(DebuggerRequest::from_json(&invalid.to_string()).is_err(), "{invalid}");
    }
    request["address"] = json!(u64::MAX - 2);
    assert!(DebuggerRequest::from_json(&request.to_string()).is_err());
    let registers = json!({"version":1, "operation":"read_registers", "expected_token":token(),
                           "thread_id":"0x1", "registers":["pc", "sp", "cpsr"]});
    assert!(DebuggerRequest::from_json(&registers.to_string()).is_ok());
    for names in [json!([]), json!(["pc", "pc"]), json!(["$pc"]), json!(["x31"]), json!(["x01"])] {
        let mut invalid = registers.clone();
        invalid["registers"] = names;
        assert!(DebuggerRequest::from_json(&invalid.to_string()).is_err());
    }
    let duplicate_token = r#"{"version":1,"operation":"describe_session","expected_token":{
        "backend":"lldb-sb","session_id":"test","process_unique_id":1,"stop_id":0,"stop_id":0,"target_index":0}}"#;
    assert!(DebuggerRequest::from_json(duplicate_token).is_err());
    for (field, value) in [("offset", json!(4097)), ("limit", json!(0)), ("limit", json!(129)), ("limit", Value::Null)]
    {
        let mut request = json!({"version":1,"operation":"list_modules","expected_token":token()});
        request[field] = value;
        assert!(DebuggerRequest::from_json(&request.to_string()).is_err());
    }
    for (field, value) in [
        ("process_unique_id", json!(0)),
        ("target_index", json!(u32::MAX)),
        ("session_id", json!("")),
        ("backend", json!("gdb")),
    ] {
        let mut bad_token = token();
        bad_token[field] = value;
        let request = json!({"version":1, "operation":"describe_session", "expected_token":bad_token});
        assert!(DebuggerRequest::from_json(&request.to_string()).is_err());
    }
}

#[test]
fn no_socket_discovery_and_expired_deadlines() {
    let error = query_debugger(Path::new("query.sock"), &describe(), Instant::now()).unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert!(query_debugger(Path::new("query.sock"), &describe(), Instant::now() + Duration::from_secs(1)).is_err());
}

#[test]
fn file_tool_schema_requires_explicit_socket_and_read_only_request() {
    let tool = rampage_api::tools::file_tools().into_iter().find(|tool| tool.name == "query_debugger").unwrap();
    assert_eq!(tool.group, rampage_api::tools::Group::Runtime);
    assert_eq!(tool.input_schema["additionalProperties"], false);
    let required = tool.input_schema["required"].as_array().unwrap();
    assert!(required.contains(&json!("socket")) && required.contains(&json!("request")));
    assert!(tool.input_schema["properties"].get("path").is_none());
    let schema = tool.input_schema.to_string();
    for operation in
        ["describe_session", "list_modules", "list_threads", "read_registers", "read_memory", "resolve_module_address"]
    {
        assert!(schema.contains(operation));
    }
    assert!(!schema.contains("command") && !schema.contains("expression") && !schema.contains("attach"));
    let packs = rampage_api::Packs::default();
    for input in [
        json!({"request":{"version":1,"operation":"describe_session"}}),
        json!({"socket":"/missing", "request":{"version":1,"operation":"continue"}}),
        json!({"socket":"/missing", "request":{"version":1,"operation":"describe_session"},
                         "path":"/must/not/open"}),
        json!({"socket":"/missing", "request":{"version":1,"operation":"describe_session"},
                         "timeout_ms":0}),
    ] {
        let error = tool.call(&packs, input).unwrap_err();
        assert!(error.contains("invalid") || error.contains("timeout_ms"), "{error}");
    }
    assert!(!packs.is_loaded());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::fs::{DirBuilder, Permissions};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::JoinHandle;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Socket {
        directory: PathBuf,
        path: PathBuf,
        listener: Option<UnixListener>,
    }

    impl Socket {
        fn new() -> Self {
            let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "rq-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let path = directory.join("s");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
            Self { directory, path, listener: Some(listener) }
        }

        fn serve(&mut self, run: impl FnOnce(UnixStream, Value) + Send + 'static) -> JoinHandle<()> {
            let listener = self.listener.take().unwrap();
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.ends_with('\n'));
                assert!(!line[..line.len() - 1].contains('\n'));
                assert!(line.len() - 1 <= MAX_DEBUGGER_REQUEST_BYTES);
                let request = serde_json::from_str(&line).unwrap();
                let mut trailing = Vec::new();
                reader.read_to_end(&mut trailing).unwrap();
                assert!(trailing.is_empty(), "client sent trailing requests");
                run(reader.into_inner(), request);
            })
        }

        fn response(&mut self, bytes: Vec<u8>) -> JoinHandle<()> {
            self.serve(move |mut stream, _| {
                let _ = stream.write_all(&bytes);
            })
        }

        fn query(&self, request: &DebuggerRequest) -> Result<rampage_api::DebuggerResponse, rampage_api::ApiError> {
            query_debugger(&self.path, request, Instant::now() + Duration::from_secs(3))
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn response(operation: &str) -> Value {
        json!({"protocol":"rampage-lldb-query-v1", "ok":true, "operation":operation, "token":token(),
               "data":{"state":"stopped", "stop_evidence":{"source":"SBThread.GetStopReason/current-process-stop",
                         "is_stopped":false,"stop_reason":3}},
               "observation":{"content_sha256":"0".repeat(64), "consistency":"revalidated-non-atomic",
                   "atomic_snapshot":false,
                   "identity_scope":"content hash is not stop identity or proof of a point-in-time snapshot"}})
    }

    fn line(value: &Value) -> Vec<u8> {
        format!("{value}\n").into_bytes()
    }

    #[test]
    fn real_socket_preserves_non_atomic_observation_and_stop_evidence() {
        let mut socket = Socket::new();
        let expected = response("describe_session");
        let server = socket.response(line(&expected));
        let result = socket.query(&describe()).unwrap();
        server.join().unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), expected);
        assert_eq!(std::fs::read_dir(&socket.directory).unwrap().count(), 1, "no annotations or images opened");
    }

    #[test]
    fn module_resolution_preserves_raw_qualified_results_and_null_operation_errors() {
        let request_value = resolve();
        let request = DebuggerRequest::from_json(&request_value.to_string()).unwrap();
        let mut socket = Socket::new();
        let mut expected = response("resolve_module_address");
        expected["data"] = json!({"module_uuid":request_value["module_uuid"],"module":{"index":1,"name":"same"},
            "file_address":"0x100000004","load_address":"0x1804","interpretation":"raw-addresses-only",
            "section":{"index_path":[0,0],"file_base":"0x100000000","load_base":"0x1800",
                "ancestors":[{"index_path":[0],"file_base":"0x100000000","file_end":"0x100004000",
                    "load_base":"0x1800","load_end":"0x5800"}]},
            "proven_flow":false,"proven_layout":false});
        let sent = expected.clone();
        let server = socket.serve(move |mut stream, received| {
            assert_eq!(received, request_value);
            stream.write_all(&line(&sent)).unwrap();
        });
        let result = socket.query(&request).unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), expected);
        server.join().unwrap();
        for operation in [json!("resolve_module_address"), Value::Null] {
            let mut socket = Socket::new();
            let failure = json!({"protocol":"rampage-lldb-query-v1","ok":false,"operation":operation,
                "error":{"code":"unavailable","message":"ambiguous UUID"}});
            let server = socket.response(line(&failure));
            assert_eq!(serde_json::to_value(socket.query(&request).unwrap()).unwrap(), failure);
            server.join().unwrap();
        }
    }

    #[test]
    fn backend_errors_are_preserved_without_partial_observations() {
        let request = DebuggerRequest::from_json(
            &json!({"version":1,"operation":"list_threads",
                                                        "expected_token":token()})
            .to_string(),
        )
        .unwrap();
        for code in ["stale_token", "state_changed", "backend_error", "unavailable"] {
            for operation in [json!("list_threads"), Value::Null] {
                let mut socket = Socket::new();
                let failure = json!({"protocol":"rampage-lldb-query-v1", "operation":operation, "ok":false,
                                 "error":{"code":code,"message":"controlled backend failure"}});
                let server = socket.response(line(&failure));
                let result = socket.query(&request).unwrap();
                assert!(!result.ok);
                assert_eq!(serde_json::to_value(result).unwrap(), failure);
                server.join().unwrap();
            }
        }
    }

    #[test]
    fn error_operations_must_be_explicit_and_cannot_name_another_query() {
        for operation in [None, Some(json!("read_memory"))] {
            let mut socket = Socket::new();
            let mut failure = json!({"protocol":"rampage-lldb-query-v1", "ok":false,
                "error":{"code":"unavailable","message":"controlled transport failure"}});
            if let Some(operation) = operation {
                failure["operation"] = operation;
            }
            let server = socket.response(line(&failure));
            assert!(socket.query(&describe()).is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn null_evidence_fields_cannot_substitute_for_missing_error_operation() {
        for substitute in ["data", "token", "observation"] {
            let mut socket = Socket::new();
            let mut failure = json!({"protocol":"rampage-lldb-query-v1", "ok":false,
                "error":{"code":"unavailable","message":"controlled transport failure"}});
            failure[substitute] = Value::Null;
            let server = socket.response(line(&failure));
            assert!(socket.query(&describe()).is_err(), "unexpected field {substitute}");
            server.join().unwrap();
        }
    }

    #[test]
    fn malformed_truncated_duplicate_and_trailing_frames_are_refused() {
        let valid = line(&response("describe_session"));
        let mut duplicate = String::from_utf8(valid.clone()).unwrap();
        duplicate = duplicate.replacen("\"ok\":true", "\"ok\":true,\"ok\":true", 1);
        let mut duplicate_data = String::from_utf8(valid.clone()).unwrap();
        duplicate_data =
            duplicate_data.replacen("\"state\":\"stopped\"", "\"state\":\"stopped\",\"state\":\"stopped\"", 1);
        for bytes in [
            Vec::new(),
            b"{\n".to_vec(),
            b"\xff\n".to_vec(),
            valid[..valid.len() - 1].to_vec(),
            [valid.clone(), b"{}\n".to_vec()].concat(),
            [valid.clone(), b"\n".to_vec()].concat(),
            duplicate.into_bytes(),
            duplicate_data.into_bytes(),
            [valid[..valid.len() - 1].to_vec(), b"\r\n".to_vec()].concat(),
        ] {
            let mut socket = Socket::new();
            let server = socket.response(bytes);
            assert!(socket.query(&describe()).is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn protocol_operation_tokens_and_atomicity_claims_must_match() {
        let request = DebuggerRequest::from_json(
            &json!({"version":1,"operation":"describe_session",
                                                        "expected_token":token()})
            .to_string(),
        )
        .unwrap();
        for (pointer, value) in [
            ("/protocol", json!("other-protocol")),
            ("/operation", json!("read_memory")),
            ("/token/stop_id", json!(4)),
            ("/token/session_id", json!("other-session")),
            ("/token/process_unique_id", json!(8)),
            ("/token/target_index", json!(1)),
            ("/observation/atomic_snapshot", json!(true)),
            ("/observation/consistency", json!("atomic")),
            ("/observation/content_sha256", json!("not-a-hash")),
            ("/data", Value::Null),
        ] {
            let mut socket = Socket::new();
            let mut malformed = response("describe_session");
            *malformed.pointer_mut(pointer).unwrap() = value;
            let server = socket.response(line(&malformed));
            assert!(socket.query(&request).is_err(), "{malformed}");
            server.join().unwrap();
        }
        let mut socket = Socket::new();
        let mut failure = response("describe_session");
        failure["ok"] = json!(false);
        failure["error"] = json!({"code":"stale_token","message":"stale"});
        let server = socket.response(line(&failure));
        assert!(socket.query(&request).is_err(), "partial error observation must be refused");
        server.join().unwrap();
    }

    #[test]
    fn response_limit_applies_to_utf8_bytes_and_accepts_the_exact_boundary() {
        use rampage_api::MAX_DEBUGGER_RESPONSE_BYTES;
        let request = DebuggerRequest::from_json(
            &json!({"version":1,"operation":"describe_session",
                    "response_budget":MAX_DEBUGGER_RESPONSE_BYTES})
            .to_string(),
        )
        .unwrap();
        let mut payload = response("describe_session");
        payload["data"]["padding"] = json!("");
        let overhead = payload.to_string().len();
        payload["data"]["padding"] = json!("a".repeat(MAX_DEBUGGER_RESPONSE_BYTES - overhead));
        let exact = line(&payload);
        assert_eq!(exact.len(), MAX_DEBUGGER_RESPONSE_BYTES + 1);
        let mut socket = Socket::new();
        let server = socket.response(exact.clone());
        assert!(socket.query(&request).is_ok());
        server.join().unwrap();
        for bytes in [
            [exact[..exact.len() - 1].to_vec(), b" \n".to_vec()].concat(),
            format!("{}\n", "é".repeat(MAX_DEBUGGER_RESPONSE_BYTES / 2 + 1)).into_bytes(),
        ] {
            let mut socket = Socket::new();
            let server = socket.response(bytes);
            assert!(socket.query(&request).unwrap_err().to_string().contains("budget"));
            server.join().unwrap();
        }
        let mut socket = Socket::new();
        let server = socket.response(exact);
        assert!(socket.query(&describe()).unwrap_err().to_string().contains("budget"));
        server.join().unwrap();
    }

    #[test]
    fn shared_deadline_bounds_partial_response_and_waiting_for_eof() {
        for completed_line in [false, true] {
            let mut socket = Socket::new();
            let (release, hold) = std::sync::mpsc::channel();
            let bytes = if completed_line { line(&response("describe_session")) } else { b"{\"protocol\":".to_vec() };
            let server = socket.serve(move |mut stream, _| {
                stream.write_all(&bytes).unwrap();
                hold.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            let start = Instant::now();
            let result = query_debugger(&socket.path, &describe(), start + Duration::from_millis(100));
            release.send(()).unwrap();
            server.join().unwrap();
            assert!(result.unwrap_err().to_string().contains("deadline"));
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    fn insecure_symlink_non_socket_and_stale_paths_fail_before_requests() {
        let mut socket = Socket::new();
        std::fs::set_permissions(&socket.path, Permissions::from_mode(0o666)).unwrap();
        assert!(socket.query(&describe()).unwrap_err().to_string().contains("0600"));
        std::fs::set_permissions(&socket.path, Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&socket.directory, Permissions::from_mode(0o755)).unwrap();
        assert!(socket.query(&describe()).unwrap_err().to_string().contains("0700"));
        std::fs::set_permissions(&socket.directory, Permissions::from_mode(0o700)).unwrap();
        let alias = socket.directory.join("link");
        symlink(&socket.path, &alias).unwrap();
        assert!(query_debugger(&alias, &describe(), Instant::now() + Duration::from_secs(1)).is_err());
        let directory_alias = socket.directory.join("dirlink");
        symlink(&socket.directory, &directory_alias).unwrap();
        assert!(
            query_debugger(&directory_alias.join("s"), &describe(), Instant::now() + Duration::from_secs(1)).is_err()
        );
        let file = socket.directory.join("file");
        std::fs::write(&file, "not a socket").unwrap();
        std::fs::set_permissions(&file, Permissions::from_mode(0o600)).unwrap();
        assert!(query_debugger(&file, &describe(), Instant::now() + Duration::from_secs(1)).is_err());
        socket.listener.take();
        assert!(socket.query(&describe()).is_err(), "stale socket must fail without attaching anything");
    }
}

#[cfg(not(unix))]
#[test]
fn non_unix_is_explicitly_unavailable() {
    let error = query_debugger(Path::new("/explicit/socket"), &describe(), Instant::now() + Duration::from_secs(1))
        .unwrap_err();
    assert!(error.to_string().contains("Unix"));
}
