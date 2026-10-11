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

MAX_MODULES = 4096
MAX_MODULE_SECTIONS = 16384


def module_uuid(value: str) -> str:
    compact = len(value) == 32 and all(
        character in "0123456789abcdefABCDEF" for character in value
    )
    dashed = len(value) == 36 and all(
        character == "-"
        if index in {8, 13, 18, 23}
        else character in "0123456789abcdefABCDEF"
        for index, character in enumerate(value)
    )
    if not compact and not dashed:
        raise ValueError("module selection requires a compact or standard dashed UUID")
    return value.replace("-", "").lower()


def module_identity(value: str) -> str:
    try:
        return module_uuid(value)
    except ValueError:
        return value


def loaded_modules(target: Any, lldb: Any) -> list[tuple[Any, dict[str, str]]]:
    count = target.GetNumModules()
    if count < 0 or count > MAX_MODULES:
        raise ValueError("capture exceeds module inspection limit")
    modules: list[tuple[Any, dict[str, str]]] = []
    seen: set[str] = set()
    for index in range(count):
        module = target.GetModuleAtIndex(index)
        header = module.GetObjectFileHeaderAddress()
        runtime_base, image_base = (
            header.GetLoadAddress(target),
            header.GetFileAddress(),
        )
        uuid = module.GetUUIDString()
        if (
            not uuid
            or runtime_base == lldb.LLDB_INVALID_ADDRESS
            or image_base == lldb.LLDB_INVALID_ADDRESS
        ):
            continue
        identity = module_identity(uuid)
        if identity in seen:
            raise ValueError("module UUID has ambiguous loaded mappings")
        seen.add(identity)
        if not 0 <= image_base < 2**64 - 1 or not 0 <= runtime_base < 2**64 - 1:
            raise ValueError("invalid module header address")
        modules.append(
            (
                module,
                {
                    "name": module.GetFileSpec().GetFilename(),
                    "path": str(module.GetFileSpec()),
                    "uuid": uuid,
                    "image_base": hex(image_base),
                    "runtime_base": hex(runtime_base),
                },
            )
        )
    return modules


def module_ranges(
    module: Any, target: Any, lldb: Any, budget: list[int] | None = None
) -> list[tuple[int, int, int]]:
    if budget is None:
        budget = [MAX_MODULE_SECTIONS]
    count = module.GetNumSections()
    if count < 0 or count > budget[0]:
        raise ValueError("module exceeds section inspection limit")
    pending = [module.GetSectionAtIndex(index) for index in range(count)]
    ranges: list[tuple[int, int, int]] = []
    while pending:
        section = pending.pop()
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError("module exceeds section inspection limit")
        children = section.GetNumSubSections()
        if children < 0 or len(pending) + children > budget[0]:
            raise ValueError("module exceeds section inspection limit")
        if children:
            pending.extend(
                section.GetSubSectionAtIndex(index) for index in range(children)
            )
            continue
        image, runtime, size = (
            section.GetFileAddress(),
            section.GetLoadAddress(target),
            section.GetByteSize(),
        )
        if (
            image == lldb.LLDB_INVALID_ADDRESS
            or runtime == lldb.LLDB_INVALID_ADDRESS
            or size == 0
        ):
            continue
        if (
            image < 0
            or runtime < 0
            or size < 0
            or max(image, runtime) + size > 2**64 - 1
        ):
            raise ValueError("invalid loaded section range")
        ranges.append((image, runtime, size))
    ranges.sort()
    return ranges


def resolve_module_range(
    selection: str,
    modules: list[tuple[Any, dict[str, str]]],
    target: Any,
    lldb: Any,
    ranges: dict[str, list[tuple[int, int, int]]],
    size: int,
    budget: list[int] | None = None,
) -> int:
    raw_uuid, raw_address = selection.split(":", 1)
    wanted, image = module_uuid(raw_uuid), int(raw_address, 0)
    matches = [
        (module, metadata)
        for module, metadata in modules
        if module_identity(metadata["uuid"]) == wanted
    ]
    if len(matches) != 1:
        raise ValueError("selected UUID is not a uniquely loaded module")
    module, metadata = matches[0]
    machine = module.GetTriple().split("-")[0]
    target_machine = target.GetTriple().split("-")[0]
    if machine.replace("arm64e", "arm64") != target_machine.replace("arm64e", "arm64"):
        raise ValueError("selected module architecture differs from capture target")
    image_base, runtime_base = (
        int(metadata["image_base"], 16),
        int(metadata["runtime_base"], 16),
    )
    if image < image_base or size <= 0 or image + size > 2**64 - 1:
        raise ValueError("invalid original-image range")
    runtime = runtime_base + image - image_base
    if runtime + size > 2**64 - 1:
        raise ValueError("module slide overflows runtime range")
    if wanted not in ranges:
        ranges[wanted] = module_ranges(module, target, lldb, budget)
    current, end = image, image + size
    for file_address, load_address, length in ranges[wanted]:
        if (
            (file_address < end and image < file_address + length)
            or (load_address < runtime + size and runtime < load_address + length)
        ) and load_address - file_address != runtime_base - image_base:
            raise ValueError(
                "selected section does not match the recorded header slide"
            )
    for file_address, load_address, length in ranges[wanted]:
        if file_address > current:
            break
        if current < file_address + length:
            current = min(end, file_address + length)
            if current == end:
                return runtime
    raise ValueError(
        "selected original-image range is not covered by loaded module sections"
    )


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
        "--region", action="append", default=[], metavar="ADDRESS:SIZE:PERMS"
    )
    parser.add_argument(
        "--module-region",
        action="append",
        default=[],
        metavar="UUID:IMAGE_ADDRESS:SIZE:PERMS",
    )
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument(
        "--module-seed", action="append", default=[], metavar="UUID:IMAGE_ADDRESS"
    )
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
        if not arguments.region and not arguments.module_region:
            raise ValueError("select at least one explicit region or module region")
        if len(arguments.region) + len(arguments.module_region) > 4096:
            raise ValueError("capture exceeds the 4096-region limit")
        modules = loaded_modules(target, lldb)
        ranges: dict[str, list[tuple[int, int, int]]] = {}
        section_budget = [MAX_MODULE_SECTIONS]
        selected = list(arguments.region)
        for specification in arguments.module_region:
            uuid, image, raw_size, permissions = specification.split(":", 3)
            size = int(raw_size, 0)
            if size <= 0 or size > 64 * 1024 * 1024:
                raise ValueError("invalid module region size")
            runtime = resolve_module_range(
                f"{uuid}:{image}", modules, target, lldb, ranges, size, section_budget
            )
            selected.append(f"{runtime:#x}:{size}:{permissions}")
        specifications: list[tuple[int, int, str]] = []
        seeds = [int(seed, 0) for seed in arguments.seed]
        if len(seeds) + len(arguments.module_seed) > 4096:
            raise ValueError("capture exceeds seed limit")
        seeds.extend(
            resolve_module_range(
                selection, modules, target, lldb, ranges, 1, section_budget
            )
            for selection in arguments.module_seed
        )
        total = 0
        for specification in selected:
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
        snapshot["modules"] = [metadata for _, metadata in modules]
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
