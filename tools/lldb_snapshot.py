from __future__ import annotations

import argparse
import importlib
import json
import os
import shlex
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn


class CommandParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise ValueError(message or self.format_help())


def validate_memory_permissions(
    process: Any, specifications: list[tuple[int, int, str]], lldb: Any
) -> None:
    if not hasattr(lldb, "SBMemoryRegionInfo") or not hasattr(
        process, "GetMemoryRegionInfo"
    ):
        raise ValueError("LLDB cannot inspect memory permissions; capture refused")
    mapping_queries = 0
    for address, size, requested in specifications:
        current, end = address, address + size
        while current < end:
            mapping_queries += 1
            if mapping_queries > 16384:
                raise ValueError("capture exceeds the memory-mapping query limit")
            region = lldb.SBMemoryRegionInfo()
            error = process.GetMemoryRegionInfo(current, region)
            if not error.Success() or not region.IsMapped():
                raise ValueError(f"memory mapping unavailable at {current:#x}")
            base, limit = region.GetRegionBase(), region.GetRegionEnd()
            if base > current or limit <= current or limit > 2**64 - 1:
                raise ValueError(f"invalid memory mapping bounds at {current:#x}")
            actual = "".join(
                [
                    "r" if region.IsReadable() else "-",
                    "w" if region.IsWritable() else "-",
                    "x" if region.IsExecutable() else "-",
                ]
            )
            if actual != requested or not region.IsReadable():
                raise ValueError(
                    f"permission mismatch at {current:#x}: requested {requested}, actual {actual}"
                )
            current = min(limit, end)


def cleanup_capture_file(temporary: Path | None) -> str | None:
    if temporary is None:
        return None
    try:
        temporary.unlink()
    except OSError as error:
        return f"temporary cleanup failed: {error}"
    return None


def publish_snapshot(
    snapshot: dict[str, Any], path: Path, before_publish: Callable[[], None]
) -> str | None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".rampage-capture-",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(snapshot, stream)
            stream.flush()
            os.fsync(stream.fileno())
        before_publish()
        os.link(temporary, path)
    except BaseException as error:
        warning = cleanup_capture_file(temporary)
        if warning is not None and isinstance(error, Exception):
            raise OSError(f"{error}; {warning}") from error
        raise
    return cleanup_capture_file(temporary)


def export_snapshot(
    debugger: Any, command: str, result: Any, internal_dict: dict[str, Any]
) -> None:
    """Export selected ranges from an already stopped, authorized LLDB process."""
    lldb = importlib.import_module("lldb")

    parser = CommandParser(prog="rampage-snapshot", exit_on_error=False)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--region", action="append", required=True, metavar="ADDRESS:SIZE:PERMS"
    )
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--thumb", action="store_true")
    parser.add_argument(
        "--compiler", help="explicit decompiler compiler specification ID"
    )
    try:
        arguments = parser.parse_args(shlex.split(command))
        target = debugger.GetSelectedTarget()
        process = target.GetProcess()
        if process.GetState() != lldb.eStateStopped:
            raise ValueError(
                "select an already stopped process; "
                "this command never launches or attaches"
            )
        stop_id = process.GetStopID(True)

        def ensure_stopped() -> None:
            if (
                process.GetState() != lldb.eStateStopped
                or process.GetStopID(True) != stop_id
            ):
                raise ValueError("process changed stop state during capture")

        machine = target.GetTriple().split("-")[0]
        arch = {
            "arm64": "aarch64",
            "arm64e": "aarch64",
            "x86_64": "x86_64",
            "arm": "arm",
        }.get(machine)
        if arch is None:
            raise ValueError(f"unsupported capture architecture: {machine}")
        if arguments.thumb and arch != "arm":
            raise ValueError("--thumb requires an ARM32 target")
        if arguments.compiler is not None and (
            not arguments.compiler
            or len(arguments.compiler) > 64
            or not all(
                character.isascii() and (character.isalnum() or character == "_")
                for character in arguments.compiler
            )
        ):
            raise ValueError("invalid compiler specification ID")
        if arguments.output.exists() or arguments.output.is_symlink():
            raise ValueError("output already exists")
        if len(arguments.region) > 4096:
            raise ValueError("capture exceeds the 4096-region limit")
        specifications: list[tuple[int, int, str]] = []
        seeds = [int(seed, 0) for seed in arguments.seed]
        total = 0
        for specification in arguments.region:
            raw_address, raw_size, permissions = specification.split(":")
            address, size = int(raw_address, 0), int(raw_size, 0)
            if size <= 0 or address < 0 or address + size > 2**64 - 1:
                raise ValueError("invalid region address or size")
            if permissions not in {"r--", "rw-", "r-x", "rwx"}:
                raise ValueError("permissions must be r--, rw-, r-x or rwx")
            if arguments.thumb and "x" in permissions and address % 2:
                raise ValueError("Thumb executable regions require even addresses")
            total += size
            specifications.append((address, size, permissions))
        if total > 64 * 1024 * 1024:
            raise ValueError("capture exceeds the 64 MiB limit")
        specifications.sort()
        for index in range(1, len(specifications)):
            previous, current = specifications[index - 1], specifications[index]
            if previous[0] + previous[1] > current[0]:
                raise ValueError("capture regions overlap")
        if any(
            not any(
                at <= seed < at + size and "x" in perms
                for at, size, perms in specifications
            )
            for seed in seeds
        ):
            raise ValueError("seeds must be in captured executable regions")
        validate_memory_permissions(process, specifications, lldb)
        regions: list[dict[str, object]] = []
        for index, (address, size, permissions) in enumerate(specifications):
            ensure_stopped()
            error = lldb.SBError()
            data = process.ReadMemory(address, size, error)
            if not error.Success() or len(data) != size:
                raise ValueError(
                    f"cannot read complete region at {address:#x}: {error}"
                )
            regions.append(
                {
                    "name": f"capture_{index}",
                    "address": hex(address),
                    "permissions": permissions,
                    "bytes": data.hex(),
                    "thumb": arguments.thumb and "x" in permissions,
                }
            )
        snapshot = {
            "format": "rampage-snapshot-v1",
            "arch": arch,
            "big_endian": target.GetByteOrder() == lldb.eByteOrderBig,
            "data_big_endian": target.GetByteOrder() == lldb.eByteOrderBig,
            "provenance": (
                f"LLDB stopped-process capture, pid {process.GetProcessID()}, stop {stop_id}; "
                f"{target.GetTriple()}; LLDB ReadMemory bytes with software-breakpoint traps normalized"
            ),
            "regions": regions,
            "seeds": [hex(seed) for seed in seeds],
            "entry": None,
        }
        triple = target.GetTriple()
        platform = (
            "darwin"
            if "-apple-" in triple
            else "windows"
            if "-windows-" in triple
            else "default"
        )
        snapshot["target"] = {"platform": platform}
        if arguments.compiler is not None:
            snapshot["target"]["compiler"] = arguments.compiler
        modules: list[dict[str, str]] = []
        for index in range(target.GetNumModules()):
            module = target.GetModuleAtIndex(index)
            header = module.GetObjectFileHeaderAddress()
            runtime_base = header.GetLoadAddress(target)
            image_base = header.GetFileAddress()
            uuid = module.GetUUIDString()
            if (
                uuid
                and runtime_base != lldb.LLDB_INVALID_ADDRESS
                and image_base != lldb.LLDB_INVALID_ADDRESS
            ):
                modules.append(
                    {
                        "name": module.GetFileSpec().GetFilename(),
                        "path": str(module.GetFileSpec()),
                        "uuid": uuid,
                        "image_base": hex(image_base),
                        "runtime_base": hex(runtime_base),
                    }
                )
            if len(modules) > 4096:
                raise ValueError("capture exceeds module limit")
        registers: list[dict[str, str]] = []
        thread = process.GetSelectedThread()
        if thread.IsValid():
            frame = thread.GetFrameAtIndex(0)
            if frame.IsValid():
                names = (
                    [f"x{index}" for index in range(31)] + ["sp", "pc", "cpsr"]
                    if arch == "aarch64"
                    else []
                )
                for name in names:
                    register = frame.FindRegister(name)
                    if register.IsValid():
                        error = lldb.SBError()
                        value = register.GetValueAsUnsigned(error)
                        if not error.Success():
                            raise ValueError(f"cannot read register {name}: {error}")
                        registers.append(
                            {
                                "thread_id": hex(thread.GetThreadID()),
                                "name": name,
                                "value": hex(value),
                            }
                        )
        snapshot["modules"] = modules
        snapshot["registers"] = registers
        ensure_stopped()
        cleanup_warning = publish_snapshot(snapshot, arguments.output, ensure_stopped)
        result.AppendMessage(
            f"Exported {len(regions)} regions ({total} bytes) to {arguments.output}"
        )
        if cleanup_warning is not None:
            result.AppendMessage(f"Capture published; {cleanup_warning}")
    except (ValueError, OSError, argparse.ArgumentError) as error:
        result.SetError(f"snapshot export failed: {error}")


def __lldb_init_module(debugger: Any, internal_dict: dict[str, Any]) -> None:
    debugger.HandleCommand(
        "command script add -f lldb_snapshot.export_snapshot rampage-snapshot"
    )
