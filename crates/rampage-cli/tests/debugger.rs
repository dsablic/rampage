use assert_cmd::Command;

fn command() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command
        .env_remove("RAMPAGE_PACKS")
        .env_remove("RAMPAGE_MCP_TOOLS")
        .args(["runtime", "debugger", "query"])
        .write_stdin("");
    command
}

#[test]
fn canonical_query_requires_explicit_socket_request_and_bounded_timeout() {
    for arguments in [
        vec![],
        vec!["--request", r#"{"version":1,"operation":"describe_session"}"#],
        vec!["--socket", "/missing"],
        vec!["--socket", "/missing", "--request", "{}", "--timeout-ms", "0"],
        vec!["--socket", "/missing", "--request", "{}", "--timeout-ms", "30001"],
    ] {
        command().args(arguments).assert().code(2);
    }
    let output = command().arg("--help").output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(help.contains("--socket") && help.contains("--request") && help.contains("--timeout-ms"));
    assert!(!help.contains("<FILE>"));
}

#[cfg(unix)]
mod unix {
    use super::*;
    use serde_json::{Value, json};
    use std::fs::{DirBuilder, Permissions};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Socket {
        directory: PathBuf,
        path: PathBuf,
        listener: Option<UnixListener>,
    }

    impl Socket {
        fn new() -> Self {
            let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "rcq-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let path = directory.join("s");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
            Self { directory, path, listener: Some(listener) }
        }

        fn serve(
            &mut self,
            count: usize,
            run: impl Fn(Value) -> Value + Send + 'static,
        ) -> std::thread::JoinHandle<()> {
            let listener = self.listener.take().unwrap();
            std::thread::spawn(move || {
                for _ in 0..count {
                    let (stream, _) = listener.accept().unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let request: Value = serde_json::from_str(&line).unwrap();
                    assert!(line.ends_with('\n'));
                    assert!(
                        !line[..line.len() - 1].bytes().any(|byte| byte.is_ascii_whitespace()),
                        "request is one compact JSON line"
                    );
                    let mut trailing = Vec::new();
                    reader.read_to_end(&mut trailing).unwrap();
                    assert!(trailing.is_empty());
                    let mut stream = reader.into_inner();
                    writeln!(stream, "{}", run(request)).unwrap();
                }
            })
        }

        fn query(&self, request: &Value) -> std::process::Output {
            command().arg("--socket").arg(&self.path).arg("--request").arg(request.to_string()).output().unwrap()
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn token() -> Value {
        json!({"backend":"lldb-sb","session_id":"cli-test","process_unique_id":7,"stop_id":3,"target_index":0})
    }

    fn success(operation: &str) -> Value {
        json!({"protocol":"rampage-lldb-query-v1","ok":true,"operation":operation,"token":token(),
            "data":{"state":"stopped", "stop_evidence":{"source":"SBThread.GetStopReason/current-process-stop",
                    "is_stopped":false,"stop_reason":3}},
            "observation":{"content_sha256":"0".repeat(64),"consistency":"revalidated-non-atomic",
                           "atomic_snapshot":false,"identity_scope":"content hash is not stop identity"}})
    }

    #[test]
    fn queries_without_binary_or_sidecars_preserve_tokens_and_stop_evidence() {
        let mut socket = Socket::new();
        let server = socket.serve(2, |request| {
            assert_eq!(request["version"], 1);
            let operation = request["operation"].as_str().unwrap();
            assert!(["describe_session", "read_registers"].contains(&operation));
            if operation == "read_registers" {
                assert_eq!(request["expected_token"], token());
                assert_eq!(request["thread_id"], "0x1");
            }
            success(operation)
        });
        let first = socket.query(&json!({"version":1,"operation":"describe_session"}));
        assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
        let response: Value = serde_json::from_slice(&first.stdout).unwrap();
        let second = socket.query(&json!({"version":1,"operation":"read_registers","expected_token":response["token"],
                                        "thread_id":"0x1","registers":["pc"]}));
        assert!(second.status.success(), "{}", String::from_utf8_lossy(&second.stderr));
        let response: Value = serde_json::from_slice(&second.stdout).unwrap();
        assert_eq!(response["data"]["stop_evidence"]["is_stopped"], false);
        assert_eq!(response["observation"]["atomic_snapshot"], false);
        server.join().unwrap();
        assert_eq!(std::fs::read_dir(&socket.directory).unwrap().count(), 1);
    }

    #[test]
    fn refuses_process_commands_duplicates_and_image_options_before_connecting() {
        let socket = Socket::new();
        for request in [
            r#"{"version":1,"operation":"continue"}"#,
            r#"{"version":1,"operation":"describe_session","version":1}"#,
            r#"{"version":1,"operation":"describe_session","command":"attach 123"}"#,
        ] {
            command().arg("--socket").arg(&socket.path).arg("--request").arg(request).assert().failure();
        }
        command()
            .arg("--socket")
            .arg(&socket.path)
            .args(["--request", r#"{"version":1,"operation":"describe_session"}"#, "--image-offset", "0"])
            .assert()
            .failure();
        socket.listener.as_ref().unwrap().set_nonblocking(true).unwrap();
        assert!(socket.listener.as_ref().unwrap().accept().is_err(), "must not connect for invalid queries");
    }

    #[test]
    fn prints_backend_errors_as_valid_json_and_fails() {
        for operation in [json!("describe_session"), Value::Null] {
            let mut socket = Socket::new();
            let server = socket.serve(1, move |_| {
                json!({"protocol":"rampage-lldb-query-v1","ok":false,
            "operation":operation,"error":{"code":"stale_token","message":"backend rejected stop"}})
            });
            let output = socket.query(&json!({"version":1,"operation":"describe_session"}));
            assert!(!output.status.success());
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["error"]["code"], "stale_token");
            assert!(String::from_utf8_lossy(&output.stderr).contains("stale_token"));
            server.join().unwrap();
        }
    }

    #[test]
    fn cli_keeps_large_valid_results_instead_of_the_tool_budget() {
        let mut socket = Socket::new();
        let server = socket.serve(1, |request| {
            assert_eq!(request["response_budget"], 100000);
            let mut value = success("describe_session");
            value["data"]["padding"] = json!("a".repeat(70000));
            value
        });
        let output = socket.query(&json!({"version":1,"operation":"describe_session","response_budget":100000}));
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.stdout.len() > 60000);
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["data"]["padding"].as_str().unwrap().len(), 70000);
        server.join().unwrap();
    }

    #[test]
    fn timeout_bounds_the_actual_cli_socket_query() {
        let mut socket = Socket::new();
        let listener = socket.listener.take().unwrap();
        let (release, hold) = std::sync::mpsc::channel();
        let (connected, accepted) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            connected.send(Instant::now()).unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"{").unwrap();
            hold.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let output = command()
            .arg("--socket")
            .arg(&socket.path)
            .args(["--request", r#"{"version":1,"operation":"describe_session"}"#, "--timeout-ms", "100"])
            .output()
            .unwrap();
        release.send(()).unwrap();
        server.join().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("deadline"));
        assert!(accepted.recv().unwrap().elapsed() < Duration::from_secs(2));
    }
}
