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
MAX_CAPTURE_THREADS = 64
MAX_MEMORY_MAPPING_QUERIES = 16384


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
    if module.GetByteOrder() != target.GetByteOrder():
        raise ValueError("selected module byte order differs from capture target")
    if module.GetAddressByteSize() != target.GetAddressByteSize():
        raise ValueError("selected module address size differs from capture target")
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


def thread_context(thread: Any) -> tuple[int, int, bool]:
    if not thread.IsValid():
        raise ValueError("selected capture thread is not valid")
    identity, reason = thread.GetThreadID(), thread.GetStopReason()
    if not 0 < identity < 2**64 - 1 or reason < 0:
        raise ValueError("invalid capture thread identity or stop reason")
    return identity, reason, thread.IsStopped()


def frame_context(frame: Any) -> tuple[int, int, int]:
    if not frame.IsValid():
        raise ValueError("capture thread has no valid top frame")
    identity, pc, sp = frame.GetFrameID(), frame.GetPC(), frame.GetSP()
    if identity != 0 or not 0 <= pc < 2**64 - 1 or not 0 <= sp < 2**64 - 1:
        raise ValueError("invalid top-frame identity, PC or SP")
    return identity, pc, sp


def register_value(frame: Any, name: str, identity: int, lldb: Any) -> int | None:
    register = frame.FindRegister(name)
    if not register.IsValid():
        return None
    error = lldb.SBError()
    value = register.GetValueAsUnsigned(error)
    if not error.Success():
        raise ValueError(
            f"cannot read register {name} for thread {identity:#x}: {error}"
        )
    if not 0 <= value < 2**64:
        raise ValueError(f"invalid register {name} for thread {identity:#x}")
    return value


def arm_data_status(frame: Any, identity: int, lldb: Any) -> int:
    status = register_value(frame, "cpsr", identity, lldb)
    if status is None or status >= 2**32:
        raise ValueError(f"ARM32 thread {identity:#x} has unknown CPSR data byte order")
    if status & (1 << 9):
        raise ValueError(
            f"ARM32 thread {identity:#x} has big-endian CPSR.E data byte order"
        )
    return status


def select_threads(
    process: Any, selectors: list[str], all_threads: bool
) -> list[tuple[Any, Any, tuple[int, int, bool]]]:
    if len(selectors) > MAX_CAPTURE_THREADS:
        raise ValueError("capture exceeds the thread limit")
    if selectors:
        identities = [int(selector, 0) for selector in selectors]
        if any(not 0 < identity < 2**64 - 1 for identity in identities):
            raise ValueError("invalid requested thread ID")
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate requested thread ID")
        threads = [process.GetThreadByID(identity) for identity in identities]
    elif all_threads:
        count = process.GetNumThreads()
        if not 0 < count <= MAX_CAPTURE_THREADS:
            raise ValueError(
                "capture thread count is empty or exceeds the thread limit"
            )
        threads = [process.GetThreadAtIndex(index) for index in range(count)]
        identities = []
    else:
        thread = process.GetSelectedThread()
        threads = [thread] if thread.IsValid() else []
        identities = []
    selected: list[tuple[Any, Any, tuple[int, int, bool]]] = []
    seen: set[int] = set()
    for index, thread in enumerate(threads):
        context = thread_context(thread)
        if identities and context[0] != identities[index]:
            raise ValueError("resolved capture thread ID differs from requested ID")
        if context[0] in seen:
            raise ValueError("duplicate resolved capture thread ID")
        seen.add(context[0])
        frame = thread.GetFrameAtIndex(0)
        if not frame.IsValid():
            if not selectors and not all_threads:
                continue
            raise ValueError(f"capture thread {context[0]:#x} has no valid top frame")
        selected.append((thread, frame, context))
    return selected


def validate_memory_permissions(
    process: Any,
    specifications: list[tuple[int, int, str]],
    lldb: Any,
    budget: list[int] | None = None,
) -> None:
    if not hasattr(lldb, "SBMemoryRegionInfo") or not hasattr(
        process, "GetMemoryRegionInfo"
    ):
        raise ValueError("LLDB cannot inspect memory permissions; capture refused")
    if budget is None:
        budget = [MAX_MEMORY_MAPPING_QUERIES]
    for address, size, requested in specifications:
        current, end = address, address + size
        while current < end:
            if budget[0] <= 0:
                raise ValueError("capture exceeds the memory-mapping query limit")
            budget[0] -= 1
            region = lldb.SBMemoryRegionInfo()
            error = process.GetMemoryRegionInfo(current, region)
            if not error.Success() or not region.IsMapped():
                raise ValueError(f"memory mapping unavailable at {current:#x}")
            base, limit = region.GetRegionBase(), region.GetRegionEnd()
            if base < 0 or base > current or limit <= current or limit > 2**64 - 1:
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
    thread_selection = parser.add_mutually_exclusive_group()
    thread_selection.add_argument(
        "--thread",
        action="append",
        default=[],
        metavar="ID",
        help="capture top-frame registers; requires PC/SP and ARM32 CPSR",
    )
    thread_selection.add_argument(
        "--all-threads",
        action="store_true",
        help=f"capture all threads, at most {MAX_CAPTURE_THREADS}; requires PC/SP and ARM32 CPSR",
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

        threads = select_threads(process, arguments.thread, arguments.all_threads)
        target_context = (
            target.GetTriple(),
            target.GetByteOrder(),
            target.GetAddressByteSize(),
        )
        frames: dict[int, tuple[int, int, int]] = {}

        def ensure_stopped() -> None:
            if (
                process.GetState() != lldb.eStateStopped
                or process.GetStopID(True) != stop_id
            ):
                raise ValueError("process changed stop state during capture")
            if (
                target.GetTriple(),
                target.GetByteOrder(),
                target.GetAddressByteSize(),
            ) != target_context:
                raise ValueError("target context changed during capture")
            for thread, frame, context in threads:
                if thread_context(thread) != context or not frame.IsValid():
                    raise ValueError("thread stop context changed during capture")
                if (
                    context[0] in frames
                    and frame_context(thread.GetFrameAtIndex(0)) != frames[context[0]]
                ):
                    raise ValueError("thread top-frame context changed during capture")

        machine = target_context[0].split("-")[0]
        arch = {
            "arm64": "aarch64",
            "arm64e": "aarch64",
            "x86_64": "x86_64",
            "arm": "arm",
        }.get(machine)
        if arch is None:
            raise ValueError(f"unsupported capture architecture: {machine}")
        byte_order, address_size = target_context[1:]
        if byte_order not in {lldb.eByteOrderLittle, lldb.eByteOrderBig}:
            raise ValueError("capture target byte order is unknown or unsupported")
        if address_size != (4 if arch == "arm" else 8):
            raise ValueError("capture target address size differs from architecture")
        if byte_order == lldb.eByteOrderBig:
            raise ValueError(
                "big-endian capture cannot establish separate code/data byte order"
            )
        if arguments.thumb and arch != "arm":
            raise ValueError("--thumb requires an ARM32 target")
        frames = {context[0]: frame_context(frame) for _, frame, context in threads}
        arm_status: dict[int, int] = {}
        if arch == "arm":
            if not threads:
                raise ValueError(
                    "ARM32 capture requires a valid stopped frame to establish CPSR data byte order"
                )
            for _, frame, (identity, _, _) in threads:
                ensure_stopped()
                arm_status[identity] = arm_data_status(frame, identity, lldb)
                ensure_stopped()
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
        mapping_budget = [MAX_MEMORY_MAPPING_QUERIES]
        validate_memory_permissions(process, specifications, lldb, mapping_budget)
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
            "big_endian": byte_order == lldb.eByteOrderBig,
            "data_big_endian": byte_order == lldb.eByteOrderBig,
            "provenance": (
                f"LLDB stopped-process capture, pid {process.GetProcessID()}, stop {stop_id}; "
                f"{target_context[0]}; LLDB ReadMemory bytes with software-breakpoint traps normalized; "
                "top-frame register threads "
                + (
                    ", ".join(
                        f"{identity:#x} (stop reason {reason})"
                        for _, _, (identity, reason, _) in threads
                    )
                    or "none"
                )
            ),
            "regions": regions,
            "seeds": [hex(seed) for seed in seeds],
            "entry": None,
        }
        triple = target_context[0]
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
        names = {
            "aarch64": [f"x{index}" for index in range(31)] + ["sp", "pc", "cpsr"],
            "arm": [f"r{index}" for index in range(13)] + ["sp", "lr", "pc", "cpsr"],
            "x86_64": ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp"]
            + [f"r{index}" for index in range(8, 16)]
            + ["rip", "rflags"],
        }[arch]
        required = {"rip", "rsp"} if arch == "x86_64" else {"pc", "sp"}
        if arch == "arm":
            required.add("cpsr")
        frame_registers: dict[int, dict[str, int]] = {}
        for thread, frame, (identity, _, _) in threads:
            ensure_stopped()
            values: dict[str, int] = {}
            for name in names:
                ensure_stopped()
                value = register_value(frame, name, identity, lldb)
                ensure_stopped()
                if value is not None:
                    values[name] = value
                    registers.append(
                        {"thread_id": hex(identity), "name": name, "value": hex(value)}
                    )
            if (
                arguments.thread or arguments.all_threads
            ) and not required <= values.keys():
                missing = ", ".join(sorted(required - values.keys()))
                raise ValueError(
                    f"capture thread {identity:#x} is missing required core registers: {missing}"
                )
            pc_name, sp_name = ("rip", "rsp") if arch == "x86_64" else ("pc", "sp")
            if (pc_name in values and values[pc_name] != frames[identity][1]) or (
                sp_name in values and values[sp_name] != frames[identity][2]
            ):
                raise ValueError(
                    "captured registers differ from the thread top-frame context"
                )
            if arch == "arm" and values.get("cpsr") != arm_status[identity]:
                raise ValueError("ARM32 CPSR context changed during capture")
            frame_registers[identity] = values
        snapshot["modules"] = [metadata for _, metadata in modules]
        snapshot["registers"] = registers

        def ensure_provenance() -> None:
            ensure_stopped()
            current_modules = loaded_modules(target, lldb)
            if [metadata for _, metadata in current_modules] != snapshot["modules"]:
                raise ValueError("loaded module provenance changed during capture")
            for module, metadata in current_modules:
                identity = module_identity(metadata["uuid"])
                if identity in ranges and (
                    module.GetTriple().split("-")[0].replace("arm64e", "arm64")
                    != machine.replace("arm64e", "arm64")
                    or module.GetByteOrder() != byte_order
                    or module.GetAddressByteSize() != address_size
                ):
                    raise ValueError("selected module context changed during capture")
                if (
                    identity in ranges
                    and module_ranges(module, target, lldb, section_budget)
                    != ranges[identity]
                ):
                    raise ValueError(
                        "selected module section ranges changed during capture"
                    )
            if arguments.all_threads:
                if process.GetNumThreads() != len(threads):
                    raise ValueError("capture thread set changed during capture")
                current_threads = [
                    process.GetThreadAtIndex(index) for index in range(len(threads))
                ]
            else:
                current_threads = [
                    process.GetThreadByID(context[0]) for _, _, context in threads
                ]
            if [thread_context(thread) for thread in current_threads] != [
                context for _, _, context in threads
            ]:
                raise ValueError("capture thread set changed during capture")
            for thread in current_threads:
                identity = thread.GetThreadID()
                frame = thread.GetFrameAtIndex(0)
                if frame_context(frame) != frames[identity]:
                    raise ValueError("thread top-frame context changed during capture")
                for name in sorted(required & frame_registers[identity].keys()):
                    ensure_stopped()
                    if (
                        register_value(frame, name, identity, lldb)
                        != frame_registers[identity][name]
                    ):
                        raise ValueError(
                            "thread core-register context changed during capture"
                        )
                if (
                    arch == "arm"
                    and arm_data_status(frame, identity, lldb) != arm_status[identity]
                ):
                    raise ValueError("ARM32 CPSR context changed during capture")
            ensure_stopped()
            validate_memory_permissions(process, specifications, lldb, mapping_budget)
            ensure_stopped()

        ensure_stopped()
        cleanup_warning = publish_snapshot(
            snapshot, arguments.output, ensure_provenance
        )
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
