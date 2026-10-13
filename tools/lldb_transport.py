from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from pathlib import Path
from types import FrameType, MethodType, TracebackType
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from typing import Self

DEFAULT_MAX_REQUESTS = 32
MAX_REQUESTS = 256
DEFAULT_IDLE_TIMEOUT_MS = 60000
MAX_IDLE_TIMEOUT_MS = 300000
REQUEST_IO_TIMEOUT_MS = 3000
BIND_TIMEOUT_MS = 3000
MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_BYTES = 262144
PROTOCOL = "rampage-lldb-query-v1"
SOCKET_TIMEOUT_ERROR: type[OSError] = getattr(socket, "timeout", TimeoutError)


class TransportError(Exception):
    code: str

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CommandParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise TransportError("invalid_request", message)


def parse_options(command: str) -> argparse.Namespace:
    parser = CommandParser(
        prog="rampage-query-serve", add_help=False, allow_abbrev=False
    )
    parser.add_argument("--socket", required=True)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--idle-timeout-ms", type=int, default=DEFAULT_IDLE_TIMEOUT_MS)
    try:
        options = parser.parse_args(shlex.split(command))
    except ValueError as error:
        raise TransportError("invalid_request", "invalid command arguments") from error
    validate_limits(options.max_requests, options.idle_timeout_ms)
    return options


def validate_limits(max_requests: int, idle_timeout_ms: int) -> None:
    for value, name, maximum in (
        (max_requests, "max-requests", MAX_REQUESTS),
        (idle_timeout_ms, "idle-timeout-ms", MAX_IDLE_TIMEOUT_MS),
    ):
        if type(value) is not int or not 1 <= value <= maximum:
            raise TransportError(
                "invalid_request", f"{name} must be an integer in [1, {maximum}]"
            )


def validate_socket_path(socket_path: str) -> Path:
    if (
        not isinstance(socket_path, str)
        or not socket_path.startswith("/")
        or socket_path.startswith("//")
        or "\x00" in socket_path
        or any(component in {"", ".", ".."} for component in socket_path.split("/")[1:])
    ):
        raise TransportError(
            "invalid_request",
            "socket must be an absolute path without empty, dot or parent components",
        )
    try:
        socket_path.encode("utf-8")
    except UnicodeError as error:
        raise TransportError(
            "invalid_request", "socket path must be valid UTF-8"
        ) from error
    return Path(socket_path)


def require_private_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise TransportError(
            "invalid_request",
            "socket parent must be a preexisting same-user private 0700 directory",
        )


class DirectoryOwner:
    live: list[int]
    failure: BaseException | None

    def __init__(self) -> None:
        self.live = []
        self.failure = None

    @property
    def current(self) -> int:
        if self.failure is not None:
            raise self.failure
        return self.live[-1]

    def open(self, component: str, parent: int | None = None) -> None:
        descriptor = os.open(
            component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        self.live.append(descriptor)

    def close(self, index: int = -1) -> None:
        descriptor = self.live.pop(index)
        os.close(descriptor)

    def close_remaining(self) -> None:
        errors: list[BaseException] = []
        while self.live:
            with retain_failures(errors):
                self.close()
        raise_directory_errors(errors)


class DirectoryCleanupError(RuntimeError):
    errors: tuple[BaseException, ...]

    def __init__(self, errors: list[BaseException]) -> None:
        self.errors = tuple(errors)
        names = ", ".join(type(error).__name__ for error in errors)
        super().__init__(f"multiple directory cleanup failures: {names}")


def raise_directory_errors(errors: list[BaseException]) -> None:
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise DirectoryCleanupError(errors) from errors[0]


@contextmanager
def retain_failures(errors: list[BaseException]) -> Generator[None, None, None]:
    """Retain every failure for propagation after the remaining owned resources are drained."""
    completed = False
    with suppress(BaseException):
        try:
            yield
            completed = True
        finally:
            if not completed:
                error = sys.exc_info()[1]
                if error is not None:
                    errors.append(error)


class DirectoryGuard:
    owner: DirectoryOwner
    previous_handler: Any
    deferred: bool
    active: bool
    installed_handler: Callable[[int, FrameType | None], None]
    pending: tuple[int, FrameType | None] | None

    def __init__(self, owner: DirectoryOwner) -> None:
        self.owner = owner
        self.previous_handler = None
        self.deferred = True
        self.active = False
        self.pending = None
        self.installed_handler = self.handle_interrupt

    def __enter__(self) -> Self:
        self.previous_handler = restorable_sigint_handler()
        try:
            self.active = True
            signal.signal(signal.SIGINT, self.installed_handler)
        except BaseException:
            signal.signal(signal.SIGINT, self.previous_handler)
            self.active = False
            raise
        return self

    def handle_interrupt(self, number: int, frame: FrameType | None) -> None:
        if self.active and self.deferred:
            self.pending = number, frame
        else:
            self.invoke_previous(number, frame)

    def invoke_previous(self, number: int, frame: FrameType | None) -> None:
        previous_handler = self.live_previous_handler()
        if not callable(previous_handler):
            return
        errors: list[BaseException] = []
        with retain_failures(errors):
            previous_handler(number, frame)
        if errors:
            self.deferred = True
            self.owner.failure = errors[0]
            errors.extend(self.terminate())
            try:
                raise_directory_errors(errors)
            except BaseException as propagated:
                self.owner.failure = propagated
                raise

    def begin_body(self) -> None:
        self.deferred = False
        self.deliver_pending()

    def deliver_pending(self) -> None:
        if self.pending is not None:
            number, frame = self.pending
            self.pending = None
            self.invoke_previous(number, frame)

    def live_previous_handler(self) -> Any:
        handler = self.previous_handler
        while isinstance(handler, MethodType) and isinstance(
            handler.__self__, DirectoryGuard
        ):
            parent = handler.__self__
            if parent.active:
                break
            handler = parent.previous_handler
        return handler

    def restore_handler(self) -> None:
        current = signal.getsignal(signal.SIGINT)
        self.active = False
        if current is self.installed_handler:
            signal.signal(signal.SIGINT, self.live_previous_handler())

    def terminate(self) -> list[BaseException]:
        errors: list[BaseException] = []
        try:
            self.deferred = True
            with retain_failures(errors):
                self.owner.close_remaining()
        finally:
            try:
                if self.owner.live:
                    with retain_failures(errors):
                        self.owner.close_remaining()
            finally:
                with retain_failures(errors):
                    self.restore_handler()
        return errors

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        errors = self.terminate()
        with retain_failures(errors):
            self.deliver_pending()
        if error is not None and errors:
            errors.insert(0, error)
        if (
            error is None
            and self.owner.failure is not None
            and all(self.owner.failure is not recorded for recorded in errors)
        ):
            errors.insert(0, self.owner.failure)
        raise_directory_errors(errors)


@contextmanager
def private_directory(path: Path) -> Generator[DirectoryOwner, None, None]:
    owner = DirectoryOwner()
    with DirectoryGuard(owner) as guard:
        owner.open("/")
        for component in path.parts[1:]:
            owner.open(component, owner.current)
            owner.close(0)
        require_private_directory(os.fstat(owner.current))
        guard.begin_body()
        yield owner


def inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def verify_directory(path: Path, descriptor: int) -> None:
    with private_directory(path) as current:
        if inode_identity(os.fstat(current.current)) != inode_identity(
            os.fstat(descriptor)
        ):
            raise TransportError("unavailable", "socket parent directory changed")


def require_absent_endpoint(path: Path, directory: int) -> None:
    try:
        os.stat(path.name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise TransportError(
        "invalid_request",
        "refusing any preexisting socket endpoint; nothing was removed",
    )


def bind_helper(directory: int, channel: int, listener_fd: int, name: str) -> None:
    """Bind an inherited socket using only the helper process's cwd and restrictive umask."""
    with (
        socket.socket(fileno=channel) as status,
        socket.socket(fileno=listener_fd) as listener,
    ):
        status.settimeout(BIND_TIMEOUT_MS / 1000)
        try:
            require_private_directory(os.fstat(directory))
            require_absent_endpoint(Path(name), directory)
            os.fchdir(directory)
            os.umask(0o177)
            listener.bind(name)
            listener.listen(1)
            status.sendall(b"ready\n")
        except (TransportError, OSError) as error:
            status.sendall(f"bind failed: {error}".encode()[:1023] + b"\n")


def receive_bind_status(channel: socket.socket, deadline: float) -> None:
    message = bytearray()
    while True:
        channel.settimeout(remaining_seconds(deadline))
        chunk = channel.recv(min(512, 1025 - len(message)))
        if not chunk:
            break
        message.extend(chunk)
        if len(message) > 1024:
            raise TransportError(
                "unavailable",
                "bind helper exceeded status byte limit; endpoint may remain",
            )
    if message != b"ready\n":
        raise TransportError(
            "unavailable", "bind helper did not report readiness; endpoint may remain"
        )


@contextmanager
def defer_sigint() -> Generator[None, None, None]:
    """Defer process-wide Python SIGINT callbacks without changing any thread's signal mask."""
    previous_handler = restorable_sigint_handler()
    pending: tuple[int, FrameType | None] | None = None

    def remember_interrupt(number: int, frame: FrameType | None) -> None:
        nonlocal pending
        pending = number, frame

    try:
        signal.signal(signal.SIGINT, remember_interrupt)
        yield
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        if pending is not None and callable(previous_handler):
            previous_handler(*pending)


def restorable_sigint_handler() -> Any:
    if threading.current_thread() is not threading.main_thread():
        raise TransportError(
            "unavailable",
            "safe resource ownership requires the Python main thread",
        )
    previous_handler = signal.getsignal(signal.SIGINT)
    if not callable(previous_handler) and previous_handler != signal.SIG_IGN:
        raise TransportError(
            "unavailable",
            "safe resource ownership requires a restorable Python SIGINT handler",
        )
    return previous_handler


@contextmanager
def bind_listener(directory: int, name: str) -> Generator[socket.socket, None, None]:
    interpreter = shutil.which("python3")
    if interpreter is None:
        raise TransportError(
            "unavailable", "python3 is required for isolated local socket binding"
        )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        with defer_sigint():
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            with parent, child:
                process: subprocess.Popen[bytes] | None = None
                try:
                    process = subprocess.Popen(
                        [
                            interpreter,
                            "-I",
                            "-S",
                            str(Path(__file__).resolve()),
                            "--bind-helper",
                            str(directory),
                            str(child.fileno()),
                            str(listener.fileno()),
                            name,
                        ],
                        pass_fds=(directory, child.fileno(), listener.fileno()),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    deadline = time.monotonic() + BIND_TIMEOUT_MS / 1000
                    child.close()
                    receive_bind_status(parent, deadline)
                    process.wait(timeout=remaining_seconds(deadline))
                    if process.returncode != 0:
                        raise TransportError(
                            "unavailable",
                            "bind helper failed after readiness; endpoint may remain",
                        )
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=BIND_TIMEOUT_MS / 1000)
        yield listener


def require_same_user(connection: socket.socket) -> None:
    peer_method = getattr(connection, "getpeereid", None)
    if peer_method is not None:
        identity, _ = peer_method()
    elif hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("=3i")
        )
        _, identity, _ = struct.unpack("=3i", credentials)
    elif hasattr(socket, "LOCAL_PEERCRED"):
        credentials = connection.getsockopt(
            getattr(socket, "SOL_LOCAL", 0), socket.LOCAL_PEERCRED, 76
        )
        version, identity, groups = struct.unpack_from("=IIh", credentials)
        if version != 0 or not 1 <= groups <= 16:
            raise TransportError(
                "unavailable", "unsupported local peer credential format"
            )
    else:
        return
    if identity != os.getuid():
        raise TransportError(
            "invalid_request", "local peer must have the operator's UID"
        )


def remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError("request_timeout", "request I/O deadline expired")
    return remaining


def read_request(connection: socket.socket, deadline: float) -> str:
    received = bytearray()
    while True:
        connection.settimeout(remaining_seconds(deadline))
        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 2 - len(received)))
        if not chunk:
            raise TransportError(
                "invalid_request", "incomplete request; a terminating LF is required"
            )
        received.extend(chunk)
        newline = received.find(b"\n")
        if newline >= 0:
            if newline > MAX_REQUEST_BYTES:
                raise TransportError(
                    "limit_exceeded", "request exceeds input byte limit"
                )
            if newline != len(received) - 1:
                raise TransportError(
                    "invalid_request",
                    "connection must contain exactly one JSON request and LF",
                )
            connection.settimeout(remaining_seconds(deadline))
            if connection.recv(1):
                raise TransportError(
                    "invalid_request",
                    "request LF must be followed by write-half-close/EOF, not more bytes",
                )
            try:
                command = received[:-1].decode("utf-8")
            except UnicodeError as error:
                raise TransportError(
                    "invalid_request", "request must contain valid UTF-8 text"
                ) from error
            if "\r" in command:
                raise TransportError(
                    "invalid_request", "request must use a single LF, not CRLF"
                )
            return command
        if len(received) > MAX_REQUEST_BYTES:
            raise TransportError("limit_exceeded", "request exceeds input byte limit")


def failure_json(code: str, message: str) -> str:
    return json.dumps(
        {
            "protocol": PROTOCOL,
            "ok": False,
            "operation": None,
            "error": {"code": code, "message": message},
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def handle_connection(connection: socket.socket, query: Callable[[str], str]) -> None:
    deadline = time.monotonic() + REQUEST_IO_TIMEOUT_MS / 1000
    try:
        require_same_user(connection)
        command = read_request(connection, deadline)
        response = query(command)
        encoded = response.encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES or b"\n" in encoded or b"\r" in encoded:
            raise TransportError(
                "response_too_large", "response exceeds transport byte or framing limit"
            )
    except TransportError as error:
        encoded = failure_json(error.code, str(error)).encode("utf-8")
    except SOCKET_TIMEOUT_ERROR:
        encoded = failure_json(
            "request_timeout", "request I/O deadline expired"
        ).encode("utf-8")
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError):
        encoded = failure_json(
            "unavailable", "local query transport failed; no observation returned"
        ).encode("utf-8")
    try:
        connection.settimeout(remaining_seconds(deadline))
        connection.sendall(encoded + b"\n")
    except (TransportError, OSError):
        return


def run_server(
    socket_path: str,
    query: Callable[[str], str],
    preflight: Callable[[], None],
    max_requests: int = DEFAULT_MAX_REQUESTS,
    idle_timeout_ms: int = DEFAULT_IDLE_TIMEOUT_MS,
    ready: Callable[[], None] | None = None,
) -> int:
    """Serve serial queries on the caller's thread; close descriptors but retain all endpoint pathnames."""
    validate_limits(max_requests, idle_timeout_ms)
    path = validate_socket_path(socket_path)
    with private_directory(path.parent) as directory:
        require_absent_endpoint(path, directory.current)
        preflight()
        verify_directory(path.parent, directory.current)
        require_absent_endpoint(path, directory.current)
        with bind_listener(directory.current, path.name) as listener:
            verify_directory(path.parent, directory.current)
            if ready is not None:
                ready()
            accepted = 0
            while accepted < max_requests:
                if directory.failure is not None:
                    raise directory.failure
                listener.settimeout(idle_timeout_ms / 1000)
                try:
                    connection, _ = listener.accept()
                except SOCKET_TIMEOUT_ERROR:
                    break
                accepted += 1
                with connection:
                    verify_directory(path.parent, directory.current)
                    handle_connection(connection, query)
            return accepted


def serve_command(
    debugger: Any,
    command: str,
    result: Any,
    query: Callable[[Any, str], str],
    preflight: Callable[[Any], None],
) -> None:
    """Run the operator-started LLDB command without spawning any LLDB worker thread."""
    try:
        options = parse_options(command)
        accepted = run_server(
            options.socket,
            lambda request: query(debugger, request),
            lambda: preflight(debugger),
            max_requests=options.max_requests,
            idle_timeout_ms=options.idle_timeout_ms,
        )
        result.AppendMessage(
            f"rampage-query-serve stopped after {accepted} accepted connections; endpoint retained for operator cleanup"
        )
    except KeyboardInterrupt:
        result.AppendMessage(
            "rampage-query-serve interrupted; endpoint may remain and requires operator cleanup"
        )
    except (
        TransportError,
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        result.SetError(
            f"rampage-query-serve: {error}; endpoint may remain and requires operator cleanup"
        )


if __name__ == "__main__":
    if len(sys.argv) != 6 or sys.argv[1] != "--bind-helper":
        raise SystemExit("this module is only an internal isolated bind helper")
    bind_helper(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
