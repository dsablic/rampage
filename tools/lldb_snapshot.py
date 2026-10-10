from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path
from typing import Any, NoReturn


class CommandParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise ValueError(message or self.format_help())


def export_snapshot(
    debugger: Any, command: str, result: Any, internal_dict: dict[str, Any]
) -> None:
    """Export selected ranges from an already stopped, authorized LLDB process."""
    import lldb

    parser = CommandParser(prog="rampage-snapshot", exit_on_error=False)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--region", action="append", required=True, metavar="ADDRESS:SIZE:PERMS"
    )
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--thumb", action="store_true")
    try:
        arguments = parser.parse_args(shlex.split(command))
        target = debugger.GetSelectedTarget()
        process = target.GetProcess()
        if process.GetState() != lldb.eStateStopped:
            raise ValueError(
                "select an already stopped process; "
                "this command never launches or attaches"
            )
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
        for previous, current in zip(specifications, specifications[1:]):
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
        regions: list[dict[str, object]] = []
        for index, (address, size, permissions) in enumerate(specifications):
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
                f"LLDB stopped-process capture, pid {process.GetProcessID()}; "
                f"{target.GetTriple()}"
            ),
            "regions": regions,
            "seeds": [hex(seed) for seed in seeds],
            "entry": None,
        }
        with arguments.output.open("x", encoding="utf-8") as output:
            json.dump(snapshot, output)
        result.AppendMessage(
            f"Exported {len(regions)} regions ({total} bytes) to {arguments.output}"
        )
    except (ValueError, OSError, argparse.ArgumentError) as error:
        result.SetError(f"snapshot export failed: {error}")


def __lldb_init_module(debugger: Any, internal_dict: dict[str, Any]) -> None:
    debugger.HandleCommand(
        "command script add -f lldb_snapshot.export_snapshot rampage-snapshot"
    )
