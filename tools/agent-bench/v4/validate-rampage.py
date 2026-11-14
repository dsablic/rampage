"""Check that each suite-v4 truth is reachable with rampage's MCP tools, by calling them directly (no model).

Usage: python3 -I tools/agent-bench/v4/validate-rampage.py [--rampage target/release/rampage] [--only TASK]
       [--json OUT]

Each task gets one scripted route through the tools an agent would use (the files are copied into a private
directory under the names the harness gives them: fixture.bin and the companions), and the value read from the
tool results is compared with the manifest's truth. A route is evidence that the truth is reachable, not a
measurement of how an agent fares; the benchmark runs measure that. Some routes read a value that a model would
read the same way from the same result (an address in a decompiled listing, a field list); those reads are
scripted here by pattern and are named in each route's comment.

Exits non-zero when a route fails or reads a value other than the truth, except for the known gaps in GAPS (each a
rampage limitation this validation found, listed in docs/plans/agent-bench-v4.md); a gap whose route starts to
reach the truth also exits non-zero, so the list stays current. The regression tasks (suite v3) are not
re-validated here; their v3 runs answered them through rampage.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TASKS = ROOT / "crates/rampage-eval/tasks/v4"
NEUTRAL = ROOT / "crates/rampage-eval/tasks/h2h/neutral-v4.toml"
sys.path.insert(0, str(HERE))
import image
from mcp_client import Client, McpError

CM4 = {"profile": "cortex-m4", "offset": 0, "base_address": 0, "vector_table": True}


def raw(path: Path, **extra: Any) -> dict[str, Any]:
    return {**CM4, "length": path.stat().st_size, **extra}


class Route:
    def __init__(self, client: Client, work: Path, task: dict[str, Any]) -> None:
        self.client, self.work, self.task = client, work, task
        self.fixture = work / "fixture.bin"
        self.calls: list[str] = []

    def call(self, name: str, **arguments: Any) -> Any:
        self.calls.append(name)
        return self.client.call(name, {"path": str(self.fixture), **arguments})

    def companion(self, name: str) -> str:
        return str(self.work / name)


def result_int(result: dict[str, Any], bits: int = 32) -> int:
    assert result["stop"] == "returned", result.get("detail")
    value = int(result["result"]["hex"], 16)
    return value & ((1 << bits) - 1)


# ---------------------------------------------------------------------------------------------------------------
# Routes, one per task.


def emulate_mix(route: Route) -> dict[str, Any]:
    return {"result": result_int(route.call("evaluate_function", at="0x1002020", args=["0x00C0FFEE", 1000]))}


def emulate_libc(route: Route) -> dict[str, Any]:
    result = route.call("evaluate_function", at="0x10106cc", args=[{"buffer": {"text": "bench-v4-token"}}])
    assert [entry["name"] for entry in result["stubbed"]] == ["strlen", "memset", "memcpy"], result["stubbed"]
    return {"result": result_int(result)}


def emulate_control(route: Route) -> dict[str, Any]:
    return {"result": result_int(route.call("evaluate_function", at="0x144", args=[40000, 500]))}


def emulate_wide(route: Route) -> dict[str, Any]:
    # A 64-bit argument below 2^32 needs `bits: 64` on a 32-bit target (the tool's schema says so).
    result = route.call("evaluate_function", at="0x211b0", args=[{"value": 63728127, "bits": 64}], return_bits=64)
    return {"result": result_int(result, 64)}


def strings_rolling(route: Route) -> dict[str, Any]:
    report = route.call("string_decoding", evaluate=True)
    decoded = next(section for section in report["sections"] if section["title"].startswith("Decoded"))
    # The finding whose replayed caller block starts at the asked function.
    for finding in decoded["findings"]:
        if any("from its block at 0x1001560" in item for item in finding["evidence"]):
            return {"text": re.search(r'to "(.*)" in emulation', finding["observation"]).group(1)}
    raise AssertionError("no decoded text for 0x1001560")


def strings_alphabet(route: Route) -> dict[str, Any]:
    # string_decoding finds no candidate (a table-driven decoder; its limitations say so), so the route is the one a
    # reader of the listing takes: the asked function calls 0x10102c4 with (stack buffer, blob, 33); run that call.
    listing = route.call("disassemble", at="0x1010304", count=12)
    blob = next(row["data_ref"] for row in listing if row["text"].startswith("adr x1"))
    length = next(int(row["text"].split("#")[1]) for row in listing if row["text"].startswith("mov w2"))
    callee = next(row["flow"]["target"] for row in listing if row["flow"]["kind"] == "call")
    result = route.call("evaluate_function", at=callee, args=[{"buffer": {"size": 64}}, blob, length])
    return {"text": result["buffers"][0]["text"]}


def import_svd(route: Route) -> dict[str, Any]:
    selector = raw(route.fixture)
    applied = route.call("import_svd", raw=selector, svd=route.companion("device.svd"), apply=True)
    assert applied["applied"], applied
    return selector


def svd_registers_written(route: Route) -> dict[str, Any]:
    selector = import_svd(route)
    code = route.call("decompile", raw=selector, at="0x16c")["code"]
    # Each register store reads `PERIPHERAL.REGISTER = value;` in the decompiled listing, in program order.
    return {"registers": re.findall(r"\b([A-Z][A-Z0-9_]*\.[A-Z][A-Z0-9_]*) = ", code)}


def svd_fields_set(route: Route) -> dict[str, Any]:
    selector = import_svd(route)
    code = route.call("decompile", raw=selector, at="0x9c")["code"]
    # The last store to the control register carries the import's field comment: /* CTRL: EN|TXEN|... */.
    comment = re.findall(r"UART0\.CTRL = [^;]*; /\* CTRL: ([^*]*) \*/", code)[-1]
    return {"fields": sorted(field.split("=")[0] for field in comment.strip().split("|"))}


def svd_status_readers(route: Route) -> dict[str, Any]:
    selector = import_svd(route)
    rows = route.call("xrefs", raw=selector, to="UART0.STATUS", limit=100)["items"]
    # Rows name the function by its default name (sub_<hex address>) and say whether the access reads or writes.
    readers = {int(row["from_function"].removeprefix("sub_"), 16) for row in rows if row.get("access") == "read"}
    return {"values": sorted(readers)}


def receipt(route: Route, selector: dict[str, Any]) -> dict[str, Any]:
    return route.call("list_patches", raw=selector)["receipt"]


def patch(route: Route, selector: dict[str, Any], at: int, original: bytes, replacement: bytes) -> None:
    current = receipt(route, selector)
    route.call("patch_bytes", raw=selector, at=hex(at), original_hex=original.hex(), replacement_hex=replacement.hex(),
               allow_data=True, source_sha256=current["source_sha256"], expected_revision=current["revision_sha256"])


def fix(route: Route, selector: dict[str, Any]) -> dict[str, Any]:
    current = receipt(route, selector)
    return route.call("integrity_checks", raw=selector, fix=True, source_sha256=current["source_sha256"],
                      expected_revision=current["revision_sha256"])


def patch_values(route: Route) -> dict[str, Any]:
    selector = {"profile": "cortex-m4", "format": "ihex", "vector_table": True}
    patch(route, selector, 0x808, (115200).to_bytes(4, "little"), (57600).to_bytes(4, "little"))
    fixed = fix(route, selector)
    fields = []
    for write in fixed["fix"]["writes"]:
        fields.append([int(write["address"], 16), int.from_bytes(bytes.fromhex(write["replacement_hex"]), "little")])
    return {"fields": fields}


def export(route: Route, selector: dict[str, Any], **arguments: Any) -> Path:
    output = route.work / route.task["output"]["name"]
    current = receipt(route, selector)
    route.call("export_image", raw=selector, destination=str(output), expected_revision=current["revision_sha256"],
               **arguments)
    return output


def patch_export_srec(route: Route) -> dict[str, Any]:
    # S-records state their own addresses, so the selector needs no offset, length or base.
    selector = {"profile": "cortex-m4", "format": "srec", "vector_table": True}
    patch(route, selector, 0x80C, b"\x01", b"\x03")
    fix(route, selector)
    export(route, selector)
    return {"written": True}


def patch_export_bin(route: Route) -> dict[str, Any]:
    selector = raw(route.fixture)
    patch(route, selector, 0x810, b"BENCH-UNIT-0001", b"BENCH-UNIT-0042")
    fix(route, selector)
    export(route, selector)
    return {"written": True}


def lock(route: Route, category: str) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    selector = import_svd(route)
    report = route.call("lock_mechanisms", raw=selector, category=category)
    assert len(report["mechanisms"]) == 1, report["mechanisms"]
    mechanism = report["mechanisms"][0]
    listing = route.call("disassemble", raw=selector, at=mechanism["decision"]["function"], count=40)
    return selector, mechanism, listing


def refusal(mechanism: dict[str, Any]) -> str:
    side = mechanism["failure_path"]
    effect = next(outcome["effect"] for outcome in mechanism["outcomes"] if outcome["path"] == side)
    return {"reset": "reset", "halt": "halt", "returns": "error_return", "writes": "flag"}[effect]


def flash_loads(listing: list[dict[str, Any]], image_size: int) -> list[int]:
    """Addresses inside the image that the listing loads from: a register set to an immediate (mov/movw), then
    `ldr rA, [rB]`. The lock routes read the compared stored value this way, as a reader of the listing would;
    lock_mechanisms names the registers it consults but not plain image data."""
    registers: dict[str, int] = {}
    loads = []
    for row in listing:
        text = row["text"]
        moved = re.match(r"mov(?:w|\.w|s)? (r\d+), #(\d+)$", text)
        if moved:
            registers[moved.group(1)] = int(moved.group(2))
            continue
        loaded = re.match(r"ldr (r\d+), \[(r\d+)\]$", text)
        if loaded and loaded.group(2) in registers and registers[loaded.group(2)] < image_size:
            loads.append(registers[loaded.group(2)])
        destination = re.match(r"\w+(?:\.w)? (r\d+),", text)
        if destination and not moved:
            registers.pop(destination.group(1), None)
    return loads


def lock_binding(route: Route) -> dict[str, Any]:
    _, mechanism, listing = lock(route, "device_binding")
    ids = sorted(int(entry["at"], 16) for entry in mechanism["consults"] if entry["kind"] == "unique_id")
    (reference,) = flash_loads(listing, route.fixture.stat().st_size)
    return {"decision_function": int(mechanism["decision"]["function"], 16), "id_registers": ids,
            "reference": reference, "refusal": refusal(mechanism)}


def lock_rollback(route: Route) -> dict[str, Any]:
    _, mechanism, listing = lock(route, "anti_rollback")
    (counter,) = [int(entry["at"], 16) for entry in mechanism["consults"] if entry["kind"] == "counter"]
    (version,) = flash_loads(listing, route.fixture.stat().st_size)
    return {"decision_function": int(mechanism["decision"]["function"], 16), "counter_register": counter,
            "image_version": version, "refusal": refusal(mechanism)}


def libid(route: Route, selector: dict[str, Any] | None, wanted: dict[str, str]) -> dict[str, Any]:
    arguments = {"raw": selector} if selector else {}
    rows, offset = [], 0
    while True:
        page = route.call("identify_functions", offset=offset, limit=256, **arguments)
        rows += page.get("matches") or page.get("items") or []
        offset = page.get("next_offset") or 0
        if not offset:
            break
    names: dict[str, int] = {}
    for row in rows:
        for name in [row.get("name"), *(row.get("aliases") or [])]:
            if name:
                names.setdefault(name, int(row["address"], 16))
    return {field: names.get(name) for field, name in wanted.items()}


def libid_elf(route: Route) -> dict[str, Any]:
    return libid(route, None, {name: name for name in ["strlen", "strcmp", "strchr", "strncpy", "qsort"]})


def libid_raw(route: Route) -> dict[str, Any]:
    selector = {"profile": "cortex-m0", "offset": 0, "length": route.fixture.stat().st_size,
                "base_address": "0x08000000", "vector_table": True}
    wanted = {name: name for name in ["memset", "memmove", "malloc", "strtol"]}
    found = libid(route, selector, {**wanted, "unsigned_divide": "__udivsi3"})
    if found["unsigned_divide"] is None:
        found["unsigned_divide"] = libid(route, selector, {"x": "__aeabi_uidiv"})["x"]
    return found


# Truths the scripted tool route does not reach today, and why. An agent can still reach them by reading code (and,
# for the patching tasks, by computing the missing CRC-16 by hand), so the tasks stay; the runs will show it.
GAPS = {
    "emulate-control-thumb-elf": "evaluate_function stops with unmapped_fetch for code mapped at address 0 (the same "
                                 "function linked at 0x8000 runs and returns the truth)",
    "patch-values-cm4-hex": "integrity_checks finds the CRC-32 at 0x13fc but not the CRC-16/CCITT-FALSE at 0x840 "
                            "(table-driven routine, 16-bit value after a 64-byte range), so fix writes a CRC-32 over "
                            "the stale CRC-16; evaluate_function does not accept Raw projects",
    "patch-export-srec-cm4-srec": "as patch-values-cm4-hex: the exported image keeps a stale CRC-16 and a wrong CRC-32",
    "patch-export-bin-cm4-raw": "as patch-values-cm4-hex: the exported image keeps a stale CRC-16 and a wrong CRC-32",
    "libid-names-m0-elf": "the embedded signature set names strlen, strcmp and strchr but not strncpy or qsort",
    "libid-names-m0-raw": "the embedded signature set names __udivsi3 but not memset, memmove, malloc or strtol",
}

ROUTES: dict[str, Callable[[Route], dict[str, Any]]] = {
    "emulate-mix-x64-elf": emulate_mix,
    "emulate-libc-arm64-elf": emulate_libc,
    "emulate-control-thumb-elf": emulate_control,
    "emulate-wide-mips-elf": emulate_wide,
    "strings-rolling-x64-elf": strings_rolling,
    "strings-alphabet-arm64-elf": strings_alphabet,
    "svd-registers-written-cm4-raw": svd_registers_written,
    "svd-fields-set-cm4-raw": svd_fields_set,
    "svd-status-readers-cm4-raw": svd_status_readers,
    "patch-values-cm4-hex": patch_values,
    "patch-export-srec-cm4-srec": patch_export_srec,
    "patch-export-bin-cm4-raw": patch_export_bin,
    "lock-binding-cm4-raw": lock_binding,
    "lock-rollback-cm4-raw": lock_rollback,
    "libid-names-m0-elf": libid_elf,
    "libid-names-m0-raw": libid_raw,
}


def expected(manifest: dict[str, Any]) -> dict[str, Any]:
    answer = manifest["answer"]
    return answer["fields"] if answer["kind"] == "exact" else {answer["field"]: answer["values"]}


def same(got: dict[str, Any], want: dict[str, Any], kind: str) -> bool:
    if kind == "exact":
        return got == want
    (key, values), = want.items()
    return set(got) == {key} and sorted(map(json.dumps, got[key])) == sorted(map(json.dumps, values))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rampage", type=Path, default=ROOT / "target/release/rampage")
    parser.add_argument("--only")
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args()
    neutral = tomllib.loads(NEUTRAL.read_text())["tasks"]
    report, failures = {}, 0
    for task, route_function in ROUTES.items():
        if arguments.only and task != arguments.only:
            continue
        manifest = tomllib.loads((TASKS / f"{task}.toml").read_text())
        with tempfile.TemporaryDirectory(dir="/private/var/tmp") as directory:
            work = Path(directory)
            shutil.copy(ROOT / manifest["fixture"]["path"], work / "fixture.bin")
            for companion in manifest["fixture"].get("companions", []):
                shutil.copy(ROOT / companion["path"], work / companion["name"])
            client = Client([str(arguments.rampage), "mcp"], {"RAMPAGE_ANALYSIS_CACHE": "off"}, work)
            route = Route(client, work, neutral[task])
            client.call("enable_tools", {"groups": ["types", "formats", "detection"]})
            try:
                got = route_function(route)
                error = None
            except (McpError, AssertionError, KeyError, StopIteration, AttributeError, TypeError) as failure:
                got, error = None, f"{type(failure).__name__}: {failure}"
            artifact = None
            output_spec = neutral[task].get("output")
            if output_spec and error is None:
                produced = work / output_spec["name"]
                want_bytes = (ROOT / output_spec["expected"]).read_bytes()
                if output_spec["format"] == "binary":
                    artifact = produced.is_file() and produced.read_bytes() == want_bytes
                else:
                    decoded = image.decode_srec(produced.read_text()) if produced.is_file() else {}
                    artifact = decoded == dict(enumerate(want_bytes))
            client.close()
        want = expected(manifest)
        ok = error is None and same(got, want, manifest["answer"]["kind"]) and artifact in (None, True)
        gap = GAPS.get(task)
        failures += ok == bool(gap)
        status = "ok  " if ok and not gap else "GAP " if gap and not ok else "FAIL"
        report[task] = {"ok": ok, "known_gap": gap, "calls": route.calls, "got": got, "want": want, "error": error,
                        "artifact_ok": artifact}
        detail = "" if ok and not gap else f"\n     got {got}\n    want {want}\n   error {error}\n  artifact {artifact}"
        if gap and ok:
            detail = "\n     the known gap no longer applies: update GAPS and the plan"
        print(f"{status} {task}: {' -> '.join(route.calls)}" + (f"\n   gap {gap}" if gap and not ok else "") + detail)
    if arguments.json:
        arguments.json.write_text(json.dumps(report, indent=1) + "\n")
    reached = sum(1 for entry in report.values() if entry["ok"])
    print(f"{reached}/{len(report)} truths reached through rampage's tools by the scripted routes; "
          f"{sum(1 for entry in report.values() if entry['known_gap'] and not entry['ok'])} known gaps; "
          f"{failures} unexpected", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
