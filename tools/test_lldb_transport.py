from __future__ import annotations

import errno
import importlib.util
import inspect
import json
import os
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType, SimpleNamespace
from typing import Any

import pytest
from test_lldb_bridge import assert_error, token

pytest_plugins = ["test_lldb_bridge"]


@pytest.fixture
def transport() -> Any:
    specification = importlib.util.spec_from_file_location(
        "lldb_transport", Path(__file__).with_name("lldb_transport.py")
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@pytest.fixture
def socket_path() -> Iterator[Path]:
    root = Path(tempfile.gettempdir()).resolve()
    if (root / "opencode").is_dir():
        root /= "opencode"
    with tempfile.TemporaryDirectory(prefix="rq-", dir=root) as directory:
        parent = Path(directory)
        parent.chmod(0o700)
        yield parent / "query.sock"


def request(operation: str = "describe_session", **fields: Any) -> bytes:
    return (
        json.dumps(
            {"version": 1, "operation": operation, **fields}, separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )


def receive_response(connection: socket.socket) -> dict[str, Any]:
    chunks: list[bytes] = []
    while chunk := connection.recv(4096):
        chunks.append(chunk)
    encoded = b"".join(chunks)
    assert encoded.endswith(b"\n") and encoded.count(b"\n") == 1
    assert len(encoded) - 1 <= 262144
    response = json.loads(encoded)
    assert response["protocol"] == "rampage-lldb-query-v1"
    return response


def exchange(path: Path, payload: bytes, half_close: bool = True) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(payload)
        rejected_before_half_close = False
        if half_close:
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError as error:
                if error.errno != errno.ENOTCONN:
                    raise
                rejected_before_half_close = True
        response = receive_response(connection)
        if rejected_before_half_close:
            assert_error(response)
        return response


def serve_clients(
    transport: Any,
    environment: Any,
    path: Path,
    clients: Callable[[], None],
    max_requests: int | None,
    query: Callable[[str], str] | None = None,
    ready_hook: Callable[[], None] | None = None,
    idle_timeout_ms: int = 1000,
) -> int:
    ready = threading.Event()
    failures: list[BaseException] = []
    command_thread = threading.get_ident()

    def run_clients() -> None:
        try:
            assert ready.wait(5), "server did not become ready"
            clients()
        except (
            AssertionError,
            OSError,
            ValueError,
            RuntimeError,
            LookupError,
            pytest.fail.Exception,
        ) as error:
            failures.append(error)

    def invoke_query(command: str) -> str:
        assert threading.get_ident() == command_thread
        if query is not None:
            return query(command)
        return environment.bridge.query_json(
            environment.debugger, command, environment.api
        )

    def preflight() -> None:
        assert threading.get_ident() == command_thread
        context = environment.bridge.QueryContext(
            environment.debugger, environment.api, None
        )
        context.verify()

    def signal_ready() -> None:
        if ready_hook is not None:
            ready_hook()
        ready.set()

    client_thread = threading.Thread(target=run_clients)
    client_thread.start()
    try:
        request_limit = {} if max_requests is None else {"max_requests": max_requests}
        accepted = transport.run_server(
            str(path),
            invoke_query,
            preflight,
            idle_timeout_ms=idle_timeout_ms,
            ready=signal_ready,
            **request_limit,
        )
    finally:
        ready.set()
        client_thread.join(6)
    assert not client_thread.is_alive()
    if failures:
        raise failures[0]
    return accepted


def test_serial_queries_share_existing_identity_and_never_touch_target_control(
    transport: Any,
    environment: Any,
    socket_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_thread = threading.get_ident()
    original_selected = environment.debugger.GetSelectedTarget

    def selected_target() -> Any:
        assert threading.get_ident() == command_thread
        return original_selected()

    def forbidden(*arguments: Any, **options: Any) -> None:
        pytest.fail("transport attempted a target-control or capture operation")

    monkeypatch.setattr(environment.debugger, "GetSelectedTarget", selected_target)
    for receiver, names in (
        (
            environment.debugger,
            ["HandleCommand", "GetCommandInterpreter", "SetAsync", "SetSelectedTarget"],
        ),
        (
            environment.target,
            ["EvaluateExpression", "Launch", "Attach", "BreakpointCreateByAddress"],
        ),
        (environment.process, ["Continue", "Stop", "WriteMemory", "Kill", "Detach"]),
        (environment.thread, ["Resume", "StepInstruction", "Suspend"]),
        (environment.bridge._snapshot, ["publish_snapshot"]),
    ):
        for name in names:
            monkeypatch.setattr(receiver, name, forbidden, raising=False)

    def clients() -> None:
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600
        session = exchange(socket_path, request())
        assert session["ok"], session
        assert set(session["data"]["operations"]) == set(environment.bridge.OPERATIONS)
        expected = session["token"]
        for operation, fields in (
            ("list_modules", {"limit": 1}),
            ("list_threads", {"limit": 1}),
            ("read_registers", {"thread_id": 1, "registers": ["x0"]}),
            ("read_memory", {"address": "0x1000", "size": 4, "permissions": "r-x"}),
            (
                "resolve_module_address",
                {
                    "module_uuid": environment.target.modules[0].uuid,
                    "file_address": "0x100000004",
                },
            ),
        ):
            response = exchange(
                socket_path, request(operation, expected_token=expected, **fields)
            )
            assert response["ok"] and response["token"] == expected, response
            assert response["observation"]["atomic_snapshot"] is False

    assert serve_clients(transport, environment, socket_path, clients, 6) == 6
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)
    assert environment.process.state == environment.api.eStateStopped
    assert environment.process.reads == [(0x1000, 4)]


def test_module_resolution_errors_return_no_partial_data_over_socket(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    expected = token(environment)

    def clients() -> None:
        fields = {
            "module_uuid": environment.target.modules[0].uuid,
            "file_address": "0x100000004",
        }
        stale = dict(expected, stop_id=expected["stop_id"] + 1)
        assert_error(
            exchange(
                socket_path,
                request("resolve_module_address", expected_token=stale, **fields),
            ),
            "stale_token",
        )
        fields["module_uuid"] = "same"
        assert_error(
            exchange(
                socket_path,
                request("resolve_module_address", expected_token=expected, **fields),
            ),
            "invalid_request",
        )

    serve_clients(transport, environment, socket_path, clients, 2)
    assert environment.process.reads == environment.process.mapping_queries == []


@pytest.mark.parametrize(
    "payload,code,half_close",
    [
        (b"\n", "invalid_request", True),
        (b"{\n", "invalid_request", True),
        (b"[]\n", "invalid_request", True),
        (b"\xff\n", "invalid_request", True),
        (
            b'{"version":1,"version":1,"operation":"describe_session"}\n',
            "invalid_request",
            True,
        ),
        (b'{"version":NaN,"operation":"describe_session"}\n', "invalid_request", True),
        (b"[" * 1500 + b"\n", "invalid_request", True),
        (request() + request(), "invalid_request", True),
        (request() + b" ", "invalid_request", True),
        (request().replace(b"\n", b"\r\n"), "invalid_request", True),
        (request()[:-1], "invalid_request", True),
        (b"", "invalid_request", True),
        (b"x" * 16385, "limit_exceeded", True),
        ("é".encode() * 8193 + b"\n", "limit_exceeded", True),
    ],
)
def test_malformed_framing_and_overflow_never_return_partial_observations(
    transport: Any,
    environment: Any,
    socket_path: Path,
    payload: bytes,
    code: str,
    half_close: bool,
) -> None:
    def clients() -> None:
        assert_error(exchange(socket_path, payload, half_close), code)

    serve_clients(transport, environment, socket_path, clients, 1)
    assert environment.process.reads == environment.process.mapping_queries == []
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)


def test_exact_input_byte_bound_accepts_frame_and_extra_byte_fails(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    payload = request()[:-1]
    padding = b" " * (transport.MAX_REQUEST_BYTES - len(payload))

    def clients() -> None:
        assert exchange(socket_path, payload + padding + b"\n")["ok"]
        assert_error(
            exchange(socket_path, payload + padding + b" \n"), "limit_exceeded"
        )

    serve_clients(transport, environment, socket_path, clients, 2)


@pytest.mark.parametrize(
    "fields",
    [
        {"operation": "continue"},
        {"operation": "attach", "pid": 42},
        {"operation": "launch", "executable": "/owned/fixture"},
        {"operation": "command", "command": "expr 1"},
        {"operation": "write_memory", "address": "0x1000", "bytes_hex": "00"},
        {"operation": "capture", "output": "/owned/capture"},
        {"expression": "foo()"},
        {"plugin": "/owned/plugin"},
        {"command": "process continue"},
    ],
)
def test_malicious_control_requests_stay_inside_existing_read_only_allowlist(
    transport: Any, environment: Any, socket_path: Path, fields: dict[str, Any]
) -> None:
    def clients() -> None:
        assert_error(exchange(socket_path, request(**fields)), "invalid_request")

    serve_clients(transport, environment, socket_path, clients, 1)
    assert environment.process.reads == environment.process.mapping_queries == []


def test_stale_tokens_and_running_process_are_revalidated_for_each_connection(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    expected = token(environment)

    def clients() -> None:
        stale = dict(expected, stop_id=expected["stop_id"] + 1)
        memory = {"address": "0x1000", "size": 4, "permissions": "r-x"}
        assert_error(
            exchange(
                socket_path, request("read_memory", expected_token=stale, **memory)
            ),
            "stale_token",
        )
        environment.process.state = 2
        assert_error(exchange(socket_path, request()), "unavailable")

    serve_clients(transport, environment, socket_path, clients, 2)
    assert environment.process.reads == environment.process.mapping_queries == []


def test_changed_provenance_discards_memory_response_over_real_socket(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    expected = token(environment)
    environment.process.on_read = lambda: setattr(
        environment.process, "stop_id", expected["stop_id"] + 1
    )

    def clients() -> None:
        payload = request(
            "read_memory",
            expected_token=expected,
            address="0x1000",
            size=4,
            permissions="r-x",
        )
        assert_error(exchange(socket_path, payload), "state_changed")

    serve_clients(transport, environment, socket_path, clients, 1)


def test_slow_client_cannot_extend_deadline_and_next_connection_still_works(
    transport: Any, environment: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport, "REQUEST_IO_TIMEOUT_MS", 60)

    def clients() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(str(socket_path))
            connection.sendall(b"{")
            started = time.monotonic()
            response = connection.recv(4096)
            if response:
                assert_error(json.loads(response), "request_timeout")
            assert time.monotonic() - started < 1
        assert exchange(socket_path, request())["ok"]

    assert serve_clients(transport, environment, socket_path, clients, 2) == 2
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)


def test_absolute_deadline_is_not_reset_by_fragment_arrivals(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([0.0, 0.002, 0.004, 0.006])
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(clock))
    timeouts: list[float] = []
    reads: list[int] = []

    def receive(size: int) -> bytes:
        reads.append(size)
        return b"x"

    connection = SimpleNamespace(settimeout=timeouts.append, recv=receive)
    with pytest.raises(transport.TransportError, match="deadline"):
        transport.read_request(connection, 0.005)
    assert len(reads) == 3
    assert timeouts == pytest.approx([0.005, 0.003, 0.001])


def test_nonreading_client_has_bounded_send_deadline(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport, "REQUEST_IO_TIMEOUT_MS", 60)
    server, client = socket.socketpair()
    with server, client:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        client.sendall(request())
        client.shutdown(socket.SHUT_WR)
        started = time.monotonic()
        transport.handle_connection(
            server, lambda command: "x" * transport.MAX_RESPONSE_BYTES
        )
        assert time.monotonic() - started < 1


def test_response_overflow_is_an_error_not_a_truncated_success(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    def clients() -> None:
        assert_error(exchange(socket_path, request()), "response_too_large")

    serve_clients(
        transport,
        environment,
        socket_path,
        clients,
        1,
        query=lambda command: "x" * (transport.MAX_RESPONSE_BYTES + 1),
    )


def test_request_budget_counts_invalid_connections_not_only_successes(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    def clients() -> None:
        assert_error(exchange(socket_path, b"{\n"), "invalid_request")
        assert_error(exchange(socket_path, b"\xff\n"), "invalid_request")

    assert serve_clients(transport, environment, socket_path, clients, 2) == 2
    with (
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection,
        pytest.raises(OSError),
    ):
        connection.connect(str(socket_path))


def test_idle_timeout_closes_listener_but_retains_endpoint(
    transport: Any, socket_path: Path
) -> None:
    assert (
        transport.run_server(
            str(socket_path), lambda command: "", lambda: None, idle_timeout_ms=1
        )
        == 0
    )
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)
    with (
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection,
        pytest.raises(ConnectionRefusedError),
    ):
        connection.connect(str(socket_path))


def test_default_request_budget_is_used_when_operator_omits_override(
    transport: Any, environment: Any, socket_path: Path
) -> None:
    def clients() -> None:
        for _ in range(transport.DEFAULT_MAX_REQUESTS):
            assert exchange(socket_path, request())["ok"]

    assert (
        serve_clients(
            transport,
            environment,
            socket_path,
            clients,
            None,
        )
        == transport.DEFAULT_MAX_REQUESTS
    )
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)


def test_interrupt_closes_listener_and_retains_endpoint_and_private_directory(
    transport: Any, socket_path: Path
) -> None:
    def interrupt() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        transport.run_server(
            str(socket_path), lambda command: "", lambda: None, ready=interrupt
        )
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)
    assert socket_path.parent.is_dir()


def test_cleanup_does_not_remove_replaced_socket_inode(
    transport: Any, socket_path: Path
) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
        original: list[tuple[int, int]] = []

        def replace() -> None:
            original.append(transport.inode_identity(socket_path.lstat()))
            socket_path.unlink()
            replacement.bind(str(socket_path))
            assert transport.inode_identity(socket_path.lstat()) != original[0]
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            transport.run_server(
                str(socket_path), lambda command: "", lambda: None, ready=replace
            )
        assert stat.S_ISSOCK(socket_path.lstat().st_mode)


def test_closing_does_not_remove_any_entry_after_absolute_path_replacement(
    transport: Any, socket_path: Path
) -> None:
    private = socket_path.parent / "private"
    moved = socket_path.parent / "moved"
    private.mkdir(mode=0o700)
    endpoint = private / "query.sock"

    def replace_parent() -> None:
        private.rename(moved)
        private.mkdir(mode=0o700)
        endpoint.write_text("replacement user data")
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        transport.run_server(
            str(endpoint), lambda command: "", lambda: None, ready=replace_parent
        )
    assert endpoint.read_text() == "replacement user data"
    assert stat.S_ISSOCK((moved / endpoint.name).lstat().st_mode)


def test_path_replaced_with_symlink_during_preflight_never_binds(
    transport: Any, socket_path: Path
) -> None:
    private = socket_path.parent / "private"
    moved = socket_path.parent / "moved"
    destination = socket_path.parent / "destination"
    private.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)

    def replace_parent() -> None:
        private.rename(moved)
        private.symlink_to(destination, target_is_directory=True)

    with pytest.raises(OSError):
        transport.run_server(
            str(private / "query.sock"), lambda command: "", replace_parent
        )
    assert not (destination / "query.sock").exists()
    assert not (moved / "query.sock").exists()


def test_endpoint_created_during_preflight_is_retained_and_never_rebound(
    transport: Any, socket_path: Path
) -> None:
    with pytest.raises(transport.TransportError, match="preexisting"):
        transport.run_server(
            str(socket_path),
            lambda command: "",
            lambda: socket_path.write_text("concurrent user endpoint"),
        )
    assert socket_path.read_text() == "concurrent user endpoint"


def test_server_never_changes_parent_process_umask_cwd_or_endpoint_permissions(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*arguments: Any, **options: Any) -> None:
        pytest.fail("server changed process-global state or a replaceable endpoint")

    for name in ("chmod", "fchmod", "unlink", "umask", "chdir", "fchdir"):
        monkeypatch.setattr(transport.os, name, forbidden)
    transport.run_server(
        str(socket_path), lambda command: "", lambda: None, idle_timeout_ms=1
    )
    assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600


def test_replacement_immediately_after_bind_is_never_recorded_as_owned_or_mutated(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_bind = transport.bind_listener
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    original_unlink = os.unlink

    @contextmanager
    def replace_after_bind(
        directory: int, name: str
    ) -> Generator[socket.socket, None, None]:
        with original_bind(directory, name) as listener:
            original_unlink(name, dir_fd=directory)
            replacement.bind(str(socket_path))
            socket_path.chmod(0o640)
            yield listener

    monkeypatch.setattr(transport, "bind_listener", replace_after_bind)
    with replacement:
        transport.run_server(
            str(socket_path), lambda command: "", lambda: None, idle_timeout_ms=1
        )
        assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o640


def test_shutdown_has_no_stat_then_unlink_window_to_delete_a_replacement(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint_stats: list[str] = []
    original_stat = os.stat

    def ready() -> None:
        def record_stat(path: Any, *arguments: Any, **options: Any) -> os.stat_result:
            metadata = original_stat(path, *arguments, **options)
            if path == socket_path.name:
                endpoint_stats.append(str(path))
            return metadata

        def forbidden_unlink(*arguments: Any, **options: Any) -> None:
            pytest.fail("shutdown attempted an inode-unconditioned pathname unlink")

        monkeypatch.setattr(transport.os, "stat", record_stat)
        monkeypatch.setattr(transport.os, "unlink", forbidden_unlink)

    transport.run_server(
        str(socket_path),
        lambda command: "",
        lambda: None,
        idle_timeout_ms=1,
        ready=ready,
    )
    assert endpoint_stats == []
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)


@pytest.mark.parametrize("replacement", ["directory", "symlink"])
def test_parent_replaced_at_bind_uses_anchored_directory_not_wrong_namespace(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    private = socket_path.parent / "private"
    moved = socket_path.parent / "moved"
    destination = socket_path.parent / "destination"
    private.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    original_bind = transport.bind_listener

    @contextmanager
    def replace_at_bind(
        directory: int, name: str
    ) -> Generator[socket.socket, None, None]:
        private.rename(moved)
        if replacement == "directory":
            private.mkdir(mode=0o700)
        else:
            private.symlink_to(destination, target_is_directory=True)
        with original_bind(directory, name) as listener:
            yield listener

    monkeypatch.setattr(transport, "bind_listener", replace_at_bind)
    with pytest.raises((OSError, transport.TransportError)):
        transport.run_server(
            str(private / "query.sock"),
            lambda command: pytest.fail("unexpected query"),
            lambda: None,
        )
    assert stat.S_IMODE((moved / "query.sock").lstat().st_mode) == 0o600
    assert not (private / "query.sock").exists()
    assert not (destination / "query.sock").exists()


def track_bind_resources(
    transport: Any,
    monkeypatch: pytest.MonkeyPatch,
    reused_descriptors: list[int] | None = None,
) -> tuple[list[socket.socket], list[subprocess.Popen[Any]]]:
    owners: list[socket.socket] = []
    helpers: list[subprocess.Popen[Any]] = []
    original_socket = socket.socket
    original_spawn = subprocess.Popen

    class OwnedSocket(original_socket):
        def __init__(self, *arguments: Any, **options: Any) -> None:
            super().__init__(*arguments, **options)
            owners.append(self)

        def close(self) -> None:
            descriptor = self.fileno()
            super().close()
            if (
                reused_descriptors is not None
                and owners
                and self is owners[0]
                and descriptor >= 0
            ):
                replacement = os.open(os.devnull, os.O_RDONLY)
                if replacement != descriptor:
                    os.dup2(replacement, descriptor)
                    os.close(replacement)
                reused_descriptors.append(descriptor)

    def spawn(*arguments: Any, **options: Any) -> subprocess.Popen[Any]:
        process = original_spawn(*arguments, **options)
        helpers.append(process)
        return process

    monkeypatch.setattr(transport.socket, "socket", OwnedSocket)
    monkeypatch.setattr(transport.subprocess, "Popen", spawn)
    return owners, helpers


def assert_bind_resources_closed(
    owners: list[socket.socket], helpers: list[subprocess.Popen[Any]]
) -> None:
    assert len(owners) == 3 and all(owner.fileno() == -1 for owner in owners)
    assert len(helpers) == 1 and helpers[0].poll() is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(helpers[0].pid, os.WNOHANG)


@pytest.mark.parametrize("operation", ["open", "verify"])
@pytest.mark.parametrize("window", ["child-open", "parent-close-reuse"])
def test_worker_sigint_during_directory_transition_closes_only_live_owned_fds(
    transport: Any,
    socket_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    window: str,
) -> None:
    original_open = os.open
    original_close = os.close
    original_mask = signal.pthread_sigmask
    anchor = original_open(
        str(socket_path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    live_directory_fds: set[int] = set()
    probe: list[int] = []
    closed_parent: list[int] = []
    interrupted: list[int] = []
    worker_failures: list[BaseException] = []
    fire = threading.Event()
    sent = threading.Event()
    armed = [True]

    def handler(number: int, frame: FrameType | None) -> None:
        interrupted.append(number)
        raise KeyboardInterrupt

    def worker() -> None:
        mask = original_mask(signal.SIG_UNBLOCK, {signal.SIGINT})
        try:
            assert fire.wait(2)
            if window == "parent-close-reuse":
                descriptor = original_open(os.devnull, os.O_RDONLY)
                probe.append(descriptor)
                assert descriptor == closed_parent[0], (
                    "test did not exercise reuse of the retired parent FD"
                )
            signal.pthread_kill(threading.get_ident(), signal.SIGINT)
        except (AssertionError, OSError, RuntimeError) as error:
            worker_failures.append(error)
        finally:
            original_mask(signal.SIG_SETMASK, mask)
            sent.set()

    def trigger() -> None:
        armed[0] = False
        fire.set()
        assert sent.wait(2)
        assert not worker_failures
        assert interrupted == [], (
            "SIGINT reached the old handler inside a directory ownership transition"
        )

    def open_directory(path: Any, flags: int, *arguments: Any, **options: Any) -> int:
        descriptor = original_open(path, flags, *arguments, **options)
        if flags & os.O_DIRECTORY:
            live_directory_fds.add(descriptor)
            if (
                armed[0]
                and window == "child-open"
                and options.get("dir_fd") is not None
            ):
                trigger()
        return descriptor

    def close_directory(descriptor: int) -> None:
        owned = descriptor in live_directory_fds
        original_close(descriptor)
        live_directory_fds.discard(descriptor)
        if armed[0] and window == "parent-close-reuse" and owned:
            closed_parent.append(descriptor)
            trigger()

    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = original_mask(signal.SIG_BLOCK, {signal.SIGINT})
    protected_mask = original_mask(signal.SIG_BLOCK, set())
    caller = threading.Thread(target=worker)
    monkeypatch.setattr(transport.os, "open", open_directory)
    monkeypatch.setattr(transport.os, "close", close_directory)
    caller.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            if operation == "verify":
                transport.verify_directory(socket_path.parent, anchor)
            else:
                with transport.private_directory(socket_path.parent):
                    pytest.fail(
                        "directory creation completed without forwarding the deferred interrupt"
                    )
        caller.join(2)
        assert not caller.is_alive() and not worker_failures
        assert interrupted == [signal.SIGINT]
        assert live_directory_fds == set(), "a created directory FD leaked"
        assert signal.getsignal(signal.SIGINT) is handler
        assert original_mask(signal.SIG_BLOCK, set()) == protected_mask
        assert stat.S_ISDIR(os.fstat(anchor).st_mode)
        if probe:
            assert stat.S_ISCHR(os.fstat(probe[0]).st_mode), (
                "cleanup closed the unrelated worker's reused FD"
            )
    finally:
        fire.set()
        caller.join(2)
        signal.signal(signal.SIGINT, previous_handler)
        original_mask(signal.SIG_SETMASK, previous_mask)
        original_close(anchor)
        for descriptor in probe:
            original_close(descriptor)


@pytest.mark.parametrize("window", ["before-install", "after-install", "after-restore"])
def test_worker_directed_sigint_during_policy_setup_never_changes_any_thread_mask(
    transport: Any, monkeypatch: pytest.MonkeyPatch, window: str
) -> None:
    original_signal = signal.signal
    original_mask = signal.pthread_sigmask
    previous_mask = original_mask(signal.SIG_BLOCK, {signal.SIGINT})
    protected_mask = original_mask(signal.SIG_BLOCK, set())
    interrupts: list[int] = []
    entered: list[bool] = []
    worker_failures: list[BaseException] = []
    fire = threading.Event()
    sent = threading.Event()
    armed = [True]

    def handler(number: int, frame: FrameType | None) -> None:
        interrupts.append(number)
        raise KeyboardInterrupt

    previous_handler = original_signal(signal.SIGINT, handler)

    def worker() -> None:
        mask = original_mask(signal.SIG_UNBLOCK, {signal.SIGINT})
        try:
            assert fire.wait(2)
            signal.pthread_kill(threading.get_ident(), signal.SIGINT)
        except (AssertionError, OSError, RuntimeError) as error:
            worker_failures.append(error)
        finally:
            original_mask(signal.SIG_SETMASK, mask)
            sent.set()

    def trigger() -> None:
        armed[0] = False
        fire.set()
        assert sent.wait(2)

    def change_handler(number: int, callback: Any) -> Any:
        installing = callable(callback) and callback is not handler
        if armed[0] and installing and window == "before-install":
            trigger()
        previous = original_signal(number, callback)
        if armed[0] and (
            (installing and window == "after-install")
            or (callback is handler and window == "after-restore")
        ):
            trigger()
        return previous

    def forbidden_mask_change(*arguments: Any, **options: Any) -> None:
        pytest.fail(
            "SIGINT deferral attempted to use a thread mask as process-wide suppression"
        )

    monkeypatch.setattr(transport.signal, "signal", change_handler)
    monkeypatch.setattr(transport.signal, "pthread_sigmask", forbidden_mask_change)
    caller = threading.Thread(target=worker)
    caller.start()
    try:
        with pytest.raises(KeyboardInterrupt), transport.defer_sigint():
            entered.append(True)
        caller.join(2)
        assert not caller.is_alive() and not worker_failures
        assert interrupts == [signal.SIGINT]
        assert entered == ([] if window == "before-install" else [True])
        assert signal.getsignal(signal.SIGINT) is handler
        assert original_mask(signal.SIG_BLOCK, set()) == protected_mask
    finally:
        fire.set()
        caller.join(2)
        original_signal(signal.SIGINT, previous_handler)
        original_mask(signal.SIG_SETMASK, previous_mask)


def test_sigint_at_cleanup_entry_does_not_abandon_a_live_directory_owner(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_signal = signal.signal
    original_mask = signal.pthread_sigmask
    original_owner = transport.DirectoryOwner
    original_cleanup = original_owner.close_remaining
    owners: list[Any] = []
    interrupted: list[int] = []
    worker_failures: list[BaseException] = []
    fire = threading.Event()
    sent = threading.Event()
    armed = [False]

    class RecordedOwner(original_owner):
        def __init__(self) -> None:
            super().__init__()
            owners.append(self)

    def handler(number: int, frame: FrameType | None) -> None:
        interrupted.append(number)
        raise KeyboardInterrupt

    def worker() -> None:
        mask = original_mask(signal.SIG_UNBLOCK, {signal.SIGINT})
        try:
            assert fire.wait(2)
            signal.pthread_kill(threading.get_ident(), signal.SIGINT)
        except (AssertionError, OSError, RuntimeError) as error:
            worker_failures.append(error)
        finally:
            original_mask(signal.SIG_SETMASK, mask)
            sent.set()

    def cleanup(owner: Any) -> None:
        if armed[0]:
            armed[0] = False
            fire.set()
            assert sent.wait(2)
        original_cleanup(owner)

    previous_handler = original_signal(signal.SIGINT, handler)
    previous_mask = original_mask(signal.SIG_BLOCK, {signal.SIGINT})
    protected_mask = original_mask(signal.SIG_BLOCK, set())
    monkeypatch.setattr(transport, "DirectoryOwner", RecordedOwner)
    monkeypatch.setattr(RecordedOwner, "close_remaining", cleanup)
    caller = threading.Thread(target=worker)
    caller.start()
    try:
        with (
            pytest.raises(KeyboardInterrupt),
            transport.private_directory(socket_path.parent),
        ):
            armed[0] = True
        caller.join(2)
        assert not caller.is_alive() and not worker_failures
        assert interrupted == [signal.SIGINT]
        assert len(owners) == 1 and owners[0].live == []
        assert signal.getsignal(signal.SIGINT) is handler
        assert original_mask(signal.SIG_BLOCK, set()) == protected_mask
    finally:
        fire.set()
        caller.join(2)
        original_signal(signal.SIGINT, previous_handler)
        original_mask(signal.SIG_SETMASK, previous_mask)


@pytest.mark.parametrize(
    "failure",
    [
        KeyboardInterrupt(),
        RuntimeError("handler failed"),
        OSError(errno.EIO, "cleanup boundary failed"),
    ],
)
def test_pre_cleanup_call_fault_is_propagated_only_after_the_owner_is_drained(
    transport: Any, monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [101]
    closed: list[int] = []
    monkeypatch.setattr(transport.os, "close", closed.append)
    function = transport.DirectoryGuard.terminate
    lines, start = inspect.getsourcelines(function)
    boundary = start + next(
        index
        for index, line in enumerate(lines)
        if line.strip() == "self.owner.close_remaining()"
    )
    previous_trace = sys.gettrace()
    previous_handler = signal.getsignal(signal.SIGINT)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    injected: list[bool] = []

    def trace(frame: FrameType, event: str, argument: Any) -> Any:
        if (
            event == "line"
            and frame.f_code is function.__code__
            and frame.f_lineno == boundary
        ):
            injected.append(True)
            sys.settrace(previous_trace)
            raise failure
        return trace

    sys.settrace(trace)
    try:
        with (
            pytest.raises(type(failure)) as raised,
            transport.DirectoryGuard(owner) as guard,
        ):
            guard.begin_body()
    finally:
        sys.settrace(previous_trace)
    assert raised.value is failure
    assert injected == [True]
    assert owner.live == [] and closed == [101]
    assert signal.getsignal(signal.SIGINT) is previous_handler
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == previous_mask


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, RuntimeError])
@pytest.mark.parametrize("delivery", ["callback", "worker-signal"])
def test_first_exit_line_failure_restores_prior_handler_before_propagating(
    transport: Any,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
    delivery: str,
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [101]
    guard = transport.DirectoryGuard(owner)
    closed: list[int] = []
    calls: list[int] = []
    failure = failure_type("prior handler failed before exit setup")
    monkeypatch.setattr(transport.os, "close", closed.append)
    fire = threading.Event()
    sent = threading.Event()
    worker_failures: list[BaseException] = []
    original_mask = signal.pthread_sigmask

    def handler(number: int, frame: FrameType | None) -> None:
        calls.append(number)
        raise failure

    def worker() -> None:
        mask = original_mask(signal.SIG_UNBLOCK, {signal.SIGINT})
        try:
            assert fire.wait(2)
            signal.pthread_kill(threading.get_ident(), signal.SIGINT)
        except (AssertionError, OSError, RuntimeError) as error:
            worker_failures.append(error)
        finally:
            original_mask(signal.SIG_SETMASK, mask)
            sent.set()

    function = transport.DirectoryGuard.__exit__
    lines, start = inspect.getsourcelines(function)
    first_line = start + next(
        index
        for index, line in enumerate(lines)
        if line.strip() == "errors = self.terminate()"
    )
    previous_trace = sys.gettrace()
    injected: list[bool] = []

    def trace(frame: FrameType, event: str, argument: Any) -> Any:
        if (
            event == "line"
            and frame.f_code is function.__code__
            and frame.f_lineno == first_line
        ):
            injected.append(True)
            sys.settrace(previous_trace)
            if delivery == "worker-signal":
                fire.set()
                assert sent.wait(2)
            else:
                callback = signal.getsignal(signal.SIGINT)
                assert callable(callback)
                callback(signal.SIGINT, frame)
        return trace

    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = original_mask(signal.SIG_UNBLOCK, {signal.SIGINT})
    active_mask = original_mask(signal.SIG_BLOCK, set())
    caller = threading.Thread(target=worker) if delivery == "worker-signal" else None
    if caller is not None:
        caller.start()
    sys.settrace(trace)
    try:
        with pytest.raises(failure_type) as raised, guard:
            guard.begin_body()
        assert raised.value is failure
        assert injected == [True] and not worker_failures
        assert owner.live == [] and closed == [101]
        assert not guard.active
        assert signal.getsignal(signal.SIGINT) is handler
        assert original_mask(signal.SIG_BLOCK, set()) == active_mask
        assert calls == [signal.SIGINT]
        with pytest.raises(failure_type) as later:
            os.kill(os.getpid(), signal.SIGINT)
        assert later.value is failure and calls == [signal.SIGINT, signal.SIGINT]
        with pytest.raises(failure_type):
            guard.installed_handler(signal.SIGINT, None)
        assert calls == [signal.SIGINT] * 3
        assert guard.pending is None and closed == [101]
        assert signal.getsignal(signal.SIGINT) is handler
        assert guard.terminate() == [] and closed == [101]
        assert signal.getsignal(signal.SIGINT) is handler
    finally:
        sys.settrace(previous_trace)
        fire.set()
        if caller is not None:
            caller.join(2)
            assert not caller.is_alive()
        signal.signal(signal.SIGINT, previous_handler)
        original_mask(signal.SIG_SETMASK, previous_mask)


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, RuntimeError])
def test_nested_forwarding_failure_cannot_restore_a_terminated_guard(
    transport: Any, monkeypatch: pytest.MonkeyPatch, failure_type: type[BaseException]
) -> None:
    outer_owner, inner_owner = transport.DirectoryOwner(), transport.DirectoryOwner()
    outer_owner.live, inner_owner.live = [101], [202]
    outer, inner = (
        transport.DirectoryGuard(outer_owner),
        transport.DirectoryGuard(inner_owner),
    )
    closed: list[int] = []
    calls: list[int] = []
    failure = failure_type("nested prior handler failed")
    monkeypatch.setattr(transport.os, "close", closed.append)

    def handler(number: int, frame: FrameType | None) -> None:
        calls.append(number)
        raise failure

    function = transport.DirectoryGuard.__exit__
    lines, start = inspect.getsourcelines(function)
    first_line = start + next(
        index
        for index, line in enumerate(lines)
        if line.strip() == "errors = self.terminate()"
    )
    previous_trace = sys.gettrace()

    def trace(frame: FrameType, event: str, argument: Any) -> Any:
        if (
            event == "line"
            and frame.f_code is function.__code__
            and frame.f_lineno == first_line
            and frame.f_locals["self"] is inner
        ):
            sys.settrace(previous_trace)
            callback = signal.getsignal(signal.SIGINT)
            assert callable(callback)
            callback(signal.SIGINT, frame)
        return trace

    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    sys.settrace(trace)
    try:
        with pytest.raises(failure_type) as raised, outer:
            outer.begin_body()
            with inner:
                inner.begin_body()
        assert raised.value is failure
        assert outer_owner.live == inner_owner.live == []
        assert closed == [101, 202] and not outer.active and not inner.active
        assert signal.getsignal(signal.SIGINT) is handler
        assert outer.terminate() == inner.terminate() == []
        assert closed == [101, 202] and signal.getsignal(signal.SIGINT) is handler
        with pytest.raises(failure_type):
            os.kill(os.getpid(), signal.SIGINT)
        assert calls == [signal.SIGINT, signal.SIGINT]
    finally:
        sys.settrace(previous_trace)
        signal.signal(signal.SIGINT, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_out_of_order_parent_termination_preserves_active_child_signal_ownership(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    outer_owner, inner_owner = transport.DirectoryOwner(), transport.DirectoryOwner()
    outer_owner.live, inner_owner.live = [101], [202]
    outer, inner = (
        transport.DirectoryGuard(outer_owner),
        transport.DirectoryGuard(inner_owner),
    )
    closed: list[int] = []
    monkeypatch.setattr(transport.os, "close", closed.append)
    previous_handler = signal.getsignal(signal.SIGINT)
    with outer:
        outer.begin_body()
        with inner:
            inner.begin_body()
            assert outer.terminate() == []
            assert signal.getsignal(signal.SIGINT) is inner.installed_handler
            assert not outer.active and inner.active
        assert signal.getsignal(signal.SIGINT) is previous_handler
    assert outer_owner.live == inner_owner.live == [] and closed == [101, 202]
    assert signal.getsignal(signal.SIGINT) is previous_handler


def test_runtime_error_from_a_body_sigint_handler_drains_owner_before_propagation(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [200]
    closed: list[int] = []
    failure = RuntimeError("prior handler raised a non-cancellation exception")
    monkeypatch.setattr(transport.os, "close", closed.append)

    def handler(number: int, frame: FrameType | None) -> None:
        raise failure

    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    try:
        with (
            pytest.raises(RuntimeError) as raised,
            transport.DirectoryGuard(owner) as guard,
        ):
            guard.begin_body()
            os.kill(os.getpid(), signal.SIGINT)
        assert raised.value is failure
        assert owner.live == [] and closed == [200]
        assert signal.getsignal(signal.SIGINT) is handler
        with pytest.raises(RuntimeError) as reused:
            os.fstat(owner.current)
        assert reused.value is failure
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_caught_handler_failure_is_not_lost_at_normal_context_exit(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [200]
    closed: list[int] = []
    failure = RuntimeError("handler cancellation was caught by the body")
    monkeypatch.setattr(transport.os, "close", closed.append)

    def handler(number: int, frame: FrameType | None) -> None:
        raise failure

    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    try:
        with (
            pytest.raises(RuntimeError) as escaped,
            transport.DirectoryGuard(owner) as guard,
        ):
            guard.begin_body()
            with pytest.raises(RuntimeError):
                os.kill(os.getpid(), signal.SIGINT)
        assert escaped.value is failure
        assert owner.live == [] and closed == [200]
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_multiple_close_errors_are_reported_after_all_live_descriptors_are_retired(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [200, 201]
    failures = {
        200: OSError(errno.EIO, "first close failure"),
        201: OSError(errno.EBADF, "second close failure"),
    }
    attempts: list[int] = []

    def close(descriptor: int) -> None:
        attempts.append(descriptor)
        raise failures[descriptor]

    monkeypatch.setattr(transport.os, "close", close)
    previous_handler = signal.getsignal(signal.SIGINT)
    with (
        pytest.raises(transport.DirectoryCleanupError) as raised,
        transport.DirectoryGuard(owner),
    ):
        pass
    assert owner.live == [] and attempts == [201, 200]
    assert raised.value.errors == (failures[201], failures[200])
    assert raised.value.__cause__ is failures[201]
    owner.close_remaining()
    assert attempts == [201, 200], (
        "a retired descriptor was retried after a close error"
    )
    assert signal.getsignal(signal.SIGINT) is previous_handler


def test_handler_and_close_errors_are_both_preserved_without_reclosing_the_fd(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [200]
    handler_error = RuntimeError("handler failed")
    close_error = OSError(errno.EIO, "close failed")
    attempts: list[int] = []

    def handler(number: int, frame: FrameType | None) -> None:
        raise handler_error

    def close(descriptor: int) -> None:
        attempts.append(descriptor)
        raise close_error

    monkeypatch.setattr(transport.os, "close", close)
    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    try:
        with (
            pytest.raises(transport.DirectoryCleanupError) as raised,
            transport.DirectoryGuard(owner) as guard,
        ):
            guard.begin_body()
            os.kill(os.getpid(), signal.SIGINT)
        assert owner.live == [] and attempts == [200]
        assert raised.value.errors == (handler_error, close_error)
        assert signal.getsignal(signal.SIGINT) is handler
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


@pytest.mark.parametrize("failure_kind", [KeyboardInterrupt, RuntimeError])
def test_restoration_interrupt_preserves_preceding_close_failure(
    transport: Any,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: type[BaseException],
) -> None:
    owner = transport.DirectoryOwner()
    owner.live = [401]
    close_error = OSError(errno.EIO, "controlled close failure")
    handler_error = failure_kind("controlled restoration interruption")
    attempts: list[int] = []

    def close(descriptor: int) -> None:
        attempts.append(descriptor)
        raise close_error

    def handler(number: int, frame: FrameType | None) -> None:
        raise handler_error

    monkeypatch.setattr(transport.os, "close", close)
    function = transport.DirectoryGuard.restore_handler
    lines, start = inspect.getsourcelines(function)
    interrupt_line = start + next(
        index
        for index, line in enumerate(lines)
        if line.strip().startswith("signal.signal(signal.SIGINT,")
    )
    interrupted = False
    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_trace = sys.gettrace()

    def trace(frame: FrameType, event: str, argument: Any) -> Any:
        nonlocal interrupted
        if (
            event == "line"
            and frame.f_code is function.__code__
            and frame.f_lineno == interrupt_line
            and not interrupted
        ):
            interrupted = True
            callback = signal.getsignal(signal.SIGINT)
            assert callable(callback)
            callback(signal.SIGINT, frame)
        return trace

    try:
        sys.settrace(trace)
        with (
            pytest.raises(transport.DirectoryCleanupError) as raised,
            transport.DirectoryGuard(owner),
        ):
            pass
        assert interrupted
        assert owner.live == [] and attempts == [401]
        assert close_error in raised.value.errors
        assert handler_error in raised.value.errors
        assert signal.getsignal(signal.SIGINT) is handler
    finally:
        sys.settrace(previous_trace)
        signal.signal(signal.SIGINT, previous_handler)


@pytest.mark.parametrize("window", ["status-read", "listener-yield"])
def test_interrupt_after_bind_has_one_managed_socket_owner_and_no_fd_leak(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch, window: str
) -> None:
    owners, helpers = track_bind_resources(transport, monkeypatch)
    function, statement = (
        (transport.receive_bind_status, "message.extend(chunk)")
        if window == "status-read"
        else (transport.bind_listener.__wrapped__, "yield listener")
    )
    lines, start = inspect.getsourcelines(function)
    interrupt_line = start + next(
        index for index, line in enumerate(lines) if line.strip() == statement
    )
    interrupted: list[bool] = []
    previous_trace = sys.gettrace()

    def trace(frame: FrameType, event: str, argument: Any) -> Any:
        if (
            event == "line"
            and frame.f_code is function.__code__
            and frame.f_lineno == interrupt_line
        ):
            interrupted.append(True)
            sys.settrace(previous_trace)
            raise KeyboardInterrupt
        return trace

    previous_handler = signal.getsignal(signal.SIGINT)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    sys.settrace(trace)
    try:
        with pytest.raises(KeyboardInterrupt):
            transport.run_server(
                str(socket_path), lambda command: "", lambda: None, idle_timeout_ms=1
            )
    finally:
        sys.settrace(previous_trace)
    assert interrupted == [True]
    assert_bind_resources_closed(owners, helpers)
    assert signal.getsignal(signal.SIGINT) is previous_handler
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == previous_mask
    assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600


def test_real_sigint_between_popen_return_and_registration_is_deferred_through_reap(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owners, helpers = track_bind_resources(transport, monkeypatch)
    original_spawn = transport.subprocess.Popen
    interrupts: list[int] = []

    def handler(number: int, frame: FrameType | None) -> None:
        interrupts.append(number)
        raise KeyboardInterrupt

    def interrupted_spawn(*arguments: Any, **options: Any) -> subprocess.Popen[Any]:
        process = original_spawn(*arguments, **options)
        original_wait = process.wait

        def interrupted_wait(timeout: float | None = None) -> int:
            status = original_wait(timeout=timeout)
            os.kill(os.getpid(), signal.SIGINT)
            return status

        monkeypatch.setattr(process, "wait", interrupted_wait)
        os.kill(os.getpid(), signal.SIGINT)
        assert interrupts == []
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", interrupted_spawn)
    previous_handler = signal.signal(signal.SIGINT, handler)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    messages: list[str] = []
    errors: list[str] = []
    try:
        transport.serve_command(
            None,
            f"--socket {socket_path} --idle-timeout-ms 1",
            SimpleNamespace(AppendMessage=messages.append, SetError=errors.append),
            lambda debugger, command: pytest.fail("unexpected query"),
            lambda debugger: None,
        )
        assert signal.getsignal(signal.SIGINT) is handler
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == previous_mask
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    assert interrupts == [signal.SIGINT]
    assert not errors and len(messages) == 1
    assert "may remain" in messages[0] and "operator cleanup" in messages[0]
    assert "cleaned up" not in messages[0]
    assert_bind_resources_closed(owners, helpers)
    assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600


def test_interrupt_unwind_cannot_double_close_an_unrelated_reused_descriptor(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reused_descriptors: list[int] = []
    owners, helpers = track_bind_resources(transport, monkeypatch, reused_descriptors)

    def interrupt() -> None:
        raise KeyboardInterrupt

    try:
        with pytest.raises(KeyboardInterrupt):
            transport.run_server(
                str(socket_path), lambda command: "", lambda: None, ready=interrupt
            )
        assert_bind_resources_closed(owners, helpers)
        assert len(reused_descriptors) == 1
        assert stat.S_ISCHR(os.fstat(reused_descriptors[0]).st_mode)
    finally:
        for descriptor in reused_descriptors:
            os.close(descriptor)


def test_opaque_host_sigint_handler_fails_before_helper_launch(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owners, helpers = track_bind_resources(transport, monkeypatch)
    monkeypatch.setattr(transport.signal, "getsignal", lambda number: None)
    with pytest.raises(transport.TransportError, match="restorable"):
        transport.run_server(str(socket_path), lambda command: "", lambda: None)
    assert not helpers and all(owner.fileno() == -1 for owner in owners)
    assert not socket_path.exists()


def test_non_main_python_thread_fails_before_helper_launch(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owners, helpers = track_bind_resources(transport, monkeypatch)
    failures: list[str] = []

    def serve() -> None:
        try:
            transport.run_server(str(socket_path), lambda command: "", lambda: None)
        except transport.TransportError as error:
            failures.append(str(error))

    caller = threading.Thread(target=serve)
    caller.start()
    caller.join(2)
    assert not caller.is_alive() and len(failures) == 1 and "main thread" in failures[0]
    assert not helpers and all(owner.fileno() == -1 for owner in owners)
    assert not socket_path.exists()


def test_bind_deadline_starts_after_process_launch_not_before_unbounded_popen(
    transport: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_spawn = subprocess.Popen
    clock = [0.0]

    def delayed_spawn(*arguments: Any, **options: Any) -> subprocess.Popen[Any]:
        process = original_spawn(*arguments, **options)
        clock[0] += 10
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", delayed_spawn)
    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    assert (
        transport.run_server(
            str(socket_path), lambda command: "", lambda: None, idle_timeout_ms=1
        )
        == 0
    )
    assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600


def test_live_startup_retries_first_real_query_connect_without_probe_budget(
    transport: Any, environment: Any, socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_lldb_transport_live import initial_query

    refused = threading.Event()
    completed = threading.Event()
    responses: list[dict[str, Any]] = []
    failures: list[Exception] = []
    original_connect = socket.socket.connect

    def connect(connection: socket.socket, address: Any) -> None:
        try:
            original_connect(connection, address)
        except ConnectionRefusedError:
            refused.set()
            raise

    monkeypatch.setattr(socket.socket, "connect", connect)

    def first_query() -> None:
        try:
            process: Any = SimpleNamespace(poll=lambda: None)
            responses.append(initial_query(socket_path, process))
        except (AssertionError, OSError, ValueError, RuntimeError) as error:
            failures.append(error)
        finally:
            completed.set()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        caller = threading.Thread(target=first_query)
        caller.start()
        try:
            assert refused.wait(2), (
                "test never exercised the bound-but-not-listening window"
            )
            listener.listen(1)
            listener.settimeout(2)
            connection, _ = listener.accept()
            with connection:
                transport.handle_connection(
                    connection,
                    lambda command: environment.bridge.query_json(
                        environment.debugger, command, environment.api
                    ),
                )
            assert completed.wait(2)
        finally:
            caller.join(3)
        assert not caller.is_alive() and not failures
        assert len(responses) == 1 and responses[0]["ok"]
        listener.setblocking(False)
        with pytest.raises(BlockingIOError):
            listener.accept()


@pytest.mark.parametrize("kind", ["file", "symlink", "dangling-symlink", "socket"])
def test_preexisting_endpoint_is_never_removed_or_rebound(
    transport: Any, socket_path: Path, kind: str
) -> None:
    existing = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if kind == "file":
            socket_path.write_text("user data")
        elif kind == "socket":
            existing.bind(str(socket_path))
        else:
            socket_path.symlink_to(
                socket_path.parent
                if kind == "symlink"
                else socket_path.parent / "absent"
            )
        before = socket_path.lstat()
        with pytest.raises(transport.TransportError, match="preexisting"):
            transport.run_server(
                str(socket_path),
                lambda command: "",
                lambda: pytest.fail("unexpected preflight"),
            )
        assert transport.inode_identity(
            socket_path.lstat()
        ) == transport.inode_identity(before)
        if kind == "file":
            assert socket_path.read_text() == "user data"
    finally:
        existing.close()


@pytest.mark.parametrize("mode", [0o777, 0o755, 0o750, 0o710, 0o770, 0o1700])
def test_nonprivate_directory_is_refused_before_preflight(
    transport: Any, socket_path: Path, mode: int
) -> None:
    socket_path.parent.chmod(mode)
    try:
        with pytest.raises(transport.TransportError, match="0700"):
            transport.run_server(
                str(socket_path),
                lambda command: "",
                lambda: pytest.fail("unexpected preflight"),
            )
        assert not socket_path.exists()
    finally:
        socket_path.parent.chmod(0o700)


def test_different_owner_directory_is_refused(transport: Any) -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid() + 1)
    with pytest.raises(transport.TransportError, match="same-user"):
        transport.require_private_directory(metadata)


def test_symlinked_ancestor_and_parent_are_refused(
    transport: Any, socket_path: Path
) -> None:
    actual = socket_path.parent / "actual"
    actual.mkdir(mode=0o700)
    private = actual / "private"
    private.mkdir(mode=0o700)
    linked = socket_path.parent / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    for path in (linked / "query.sock", linked / "private" / "query.sock"):
        with pytest.raises(OSError):
            transport.run_server(
                str(path),
                lambda command: "",
                lambda: pytest.fail("unexpected preflight"),
            )
    assert not (actual / "query.sock").exists()
    assert not (private / "query.sock").exists()


@pytest.mark.parametrize(
    "path",
    ["query.sock", "/", "//private/query.sock", "/a/../query.sock", "/a/./query.sock"],
)
def test_invalid_socket_paths_are_rejected(transport: Any, path: str) -> None:
    with pytest.raises(transport.TransportError, match="absolute path"):
        transport.run_server(
            path, lambda command: "", lambda: pytest.fail("unexpected preflight")
        )


def test_missing_directory_is_not_created(transport: Any, socket_path: Path) -> None:
    missing = socket_path.parent / "missing"
    with pytest.raises(FileNotFoundError):
        transport.run_server(
            str(missing / "query.sock"), lambda command: "", lambda: None
        )
    assert not missing.exists()


@pytest.mark.parametrize("field", ["target", "process", "running"])
def test_stopped_process_preflight_occurs_before_binding(
    environment: Any, socket_path: Path, field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if field == "target":
        environment.target.valid = False
    elif field == "process":
        environment.process.valid = False
    else:
        environment.process.state = 2
    messages: list[str] = []
    errors: list[str] = []

    def forbidden_socket(*arguments: Any, **options: Any) -> None:
        pytest.fail("bound endpoint before validating stopped process")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    result = SimpleNamespace(AppendMessage=messages.append, SetError=errors.append)
    environment.bridge.serve(
        environment.debugger, f"--socket {socket_path}", result, {}
    )
    assert errors and not messages
    assert not socket_path.exists()


def test_registered_serve_callback_runs_on_command_thread(
    environment: Any, socket_path: Path
) -> None:
    messages: list[str] = []
    errors: list[str] = []
    result = SimpleNamespace(AppendMessage=messages.append, SetError=errors.append)
    environment.bridge.serve(
        environment.debugger,
        f"--socket {shlex.quote(str(socket_path))} --max-requests 1 --idle-timeout-ms 1",
        result,
        {},
    )
    assert not errors and len(messages) == 1
    assert "0 accepted" in messages[0]
    assert "operator cleanup" in messages[0]
    assert stat.S_ISSOCK(socket_path.lstat().st_mode)


@pytest.mark.parametrize(
    "arguments",
    [
        "",
        "--socket query.sock --max-requests 0",
        "--socket query.sock --max-requests 257",
        "--socket query.sock --idle-timeout-ms 0",
        "--socket query.sock --idle-timeout-ms 300001",
        "--socket query.sock --max-requests NaN",
        "--socket query.sock --expression foo",
        "--socket query.sock --help",
        "--sock query.sock",
        "--socket 'unterminated",
    ],
)
def test_command_invalid_options_are_errors_not_parser_exits(
    transport: Any, arguments: str
) -> None:
    with pytest.raises(transport.TransportError):
        transport.parse_options(arguments)


@pytest.mark.parametrize("style", ["method", "linux", "darwin"])
def test_peer_uid_mismatch_fails_closed(
    transport: Any, monkeypatch: pytest.MonkeyPatch, style: str
) -> None:
    wrong_uid = os.getuid() + 1
    for name in ("SO_PEERCRED", "LOCAL_PEERCRED"):
        monkeypatch.delattr(transport.socket, name, raising=False)
    if style == "method":
        connection = SimpleNamespace(getpeereid=lambda: (wrong_uid, os.getgid()))
    else:
        if style == "linux":
            monkeypatch.setattr(transport.socket, "SO_PEERCRED", 17, raising=False)
            credentials = struct.pack("=3i", 123, wrong_uid, os.getgid())
        else:
            monkeypatch.setattr(transport.socket, "LOCAL_PEERCRED", 1, raising=False)
            credentials = struct.pack("=IIh", 0, wrong_uid, 1) + b"\x00" * 66
        connection = SimpleNamespace(getsockopt=lambda *arguments: credentials)
    with pytest.raises(transport.TransportError, match="UID"):
        transport.require_same_user(connection)


def test_late_second_frame_is_refused_before_query_even_after_first_lf_is_read(
    transport: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, client = socket.socketpair()
    with server, client:
        client.settimeout(1)
        client.sendall(request())
        first_frame_read = threading.Event()
        original_receive = socket.socket.recv

        def receive(connection: socket.socket, size: int, flags: int = 0) -> bytes:
            chunk = original_receive(connection, size, flags)
            if connection is server and b"\n" in chunk:
                first_frame_read.set()
            return chunk

        monkeypatch.setattr(socket.socket, "recv", receive)
        sent = threading.Event()

        def send_second() -> None:
            assert first_frame_read.wait(1)
            client.sendall(request())
            client.shutdown(socket.SHUT_WR)
            sent.set()

        def query(command: str) -> str:
            pytest.fail("query executed before complete EOF-bounded framing")

        writer = threading.Thread(target=send_second)
        writer.start()
        try:
            transport.handle_connection(server, query)
        finally:
            writer.join(2)
        assert sent.is_set() and not writer.is_alive()
        server.shutdown(socket.SHUT_WR)
        assert_error(receive_response(client), "invalid_request")


def test_complete_frame_without_write_half_close_never_reaches_query(
    transport: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport, "REQUEST_IO_TIMEOUT_MS", 60)
    server, client = socket.socketpair()
    with server, client:
        client.settimeout(1)
        client.sendall(request())
        started = time.monotonic()
        transport.handle_connection(
            server, lambda command: pytest.fail("LF without EOF reached the query")
        )
        assert time.monotonic() - started < 1
        server.shutdown(socket.SHUT_WR)
        response = client.recv(4096)
        if response:
            assert_error(json.loads(response), "request_timeout")


def test_query_only_runs_after_eof_when_peer_cannot_append_a_final_extra_request(
    transport: Any,
) -> None:
    server, client = socket.socketpair()
    with server, client:
        client.settimeout(1)
        client.sendall(request())
        client.shutdown(socket.SHUT_WR)
        queries: list[str] = []

        def query(command: str) -> str:
            queries.append(command)
            with pytest.raises(OSError):
                client.sendall(request())
            return '{"protocol":"rampage-lldb-query-v1","ok":true,"data":{}}'

        transport.handle_connection(server, query)
        server.shutdown(socket.SHUT_WR)
        assert receive_response(client)["ok"] is True
        assert len(queries) == 1
