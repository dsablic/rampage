"""Finite installed-runtime profile: exactly the nine public functions in pesect.c."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "_mingw_corpus_core", ROOT / "tools/signature-corpus.py"
)
assert SPEC is not None and SPEC.loader is not None
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)
TARGET = "x86_64-windows-gnu"
SOURCE_PINS = {
    "libc/mingw/crt/pesect.c": "445b26d25d9fe5c3270df3341cbe8af6da07ae3a82d7e9bbcef548f5893eaefd",
    "libc/mingw/COPYING": "99a69660981156c21336fdb5661f89341b013c94e4bf9e1c7467b4745718397f",
    "libc/include/any-windows-any/_mingw_mac.h": "a23e0228c8b760492cd7e150221f75d1888fcb59eefaabf71b7296d903533eb1",
}
NOTICE_SHA256 = "5c2a55e0974158321a7865d53546e66b940acef0b96479f5ffe4c78af48bf8fc"
OWNED_NAMES = frozenset(
    (
        "_ValidateImageBase",
        "_FindPESection",
        "_FindPESectionByName",
        "__mingw_GetSectionForAddress",
        "__mingw_GetSectionCount",
        "_FindPESectionExec",
        "_GetPEImageBase",
        "_IsNonwritableInCurrentImage",
        "__mingw_enum_import_library_names",
    )
)


def select_member(snapshot: bytes) -> tuple[bytes, dict[str, Any]]:
    """Read one unique regular-ar pesect.obj member, never extract archive paths."""
    if snapshot[:8] != b"!<arch>\n" or len(snapshot) > 128 * 1024 * 1024:
        raise core.CorpusError("expected bounded regular libmingw32 archive")
    offset, ordinal, strings, selected = 8, 0, b"", []
    while offset < len(snapshot):
        header = snapshot[offset : offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise core.CorpusError("malformed runtime archive header")
        size = int(header[48:58])
        name = header[:16].decode().strip()
        payload = snapshot[offset + 60 : offset + 60 + size]
        if size < 0 or len(payload) != size:
            raise core.CorpusError("runtime archive member exceeds backing")
        offset += 60 + size + (size & 1)
        if offset > len(snapshot):
            raise core.CorpusError("runtime archive member padding exceeds backing")
        if name == "//":
            strings = payload
            continue
        if name in ("/", "/SYM64/"):
            continue
        if name.startswith("/") and name[1:].isdigit():
            index = int(name[1:])
            if index >= len(strings):
                raise core.CorpusError("runtime archive long name exceeds backing")
            name = strings[index:].split(b"\0", 1)[0].split(b"/\n", 1)[0].decode()
        elif name.startswith("#1/"):
            length = int(name[3:])
            if not 0 < length <= len(payload):
                raise core.CorpusError("runtime archive inline name exceeds backing")
            name, payload = payload[:length].decode().rstrip("\0\n"), payload[length:]
        else:
            name = name.rstrip("/")
        if PurePosixPath(name).name == "pesect.obj":
            if not re.fullmatch(r"zig-global-cache/o/[0-9a-f]{32}/pesect\.obj", name):
                raise core.CorpusError(
                    "pesect member must have the fixed producer cache name"
                )
            selected.append(
                (
                    payload,
                    {
                        "member": name,
                        "ordinal": ordinal,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    },
                )
            )
        ordinal += 1
        if ordinal > 10000:
            raise core.CorpusError("runtime archive member count exceeds bound")
    if len(selected) != 1:
        raise core.CorpusError("pesect.obj archive member must be present and unique")
    return selected[0]


def validate_object(payload: bytes) -> None:
    """Reject any selected member with a different predeclared external function universe."""
    if len(payload) < 20 or struct.unpack_from("<H", payload)[0] != 0x8664:
        raise core.CorpusError("pesect member must be regular x64 COFF")
    pointer, count = struct.unpack_from("<II", payload, 8)
    sections = struct.unpack_from("<H", payload, 2)[0]
    strings = pointer + 18 * count
    if (
        count > 10000
        or not 0 < sections <= 4096
        or pointer < 20 + 40 * sections
        or strings + 4 > len(payload)
    ):
        raise core.CorpusError("pesect COFF symbol table exceeds backing")
    names, index = [], 0
    while index < count:
        symbol = payload[pointer + index * 18 : pointer + (index + 1) * 18]
        section, kind, storage, auxiliary = struct.unpack_from("<hHBB", symbol, 12)
        if section > 0 and kind == 0x20 and storage == 2:
            if (
                section > sections
                or not struct.unpack_from("<I", payload, 20 + 40 * (section - 1) + 36)[
                    0
                ]
                & 0x20000000
            ):
                raise core.CorpusError(
                    "pesect function is not in an executable COFF section"
                )
            name = symbol[:8].rstrip(b"\0")
            if symbol[:4] == b"\0" * 4:
                start = strings + struct.unpack_from("<I", symbol, 4)[0]
                name = payload[start:].split(b"\0", 1)[0]
            names.append(name.decode())
        index += auxiliary + 1
        if index > count:
            raise core.CorpusError("pesect COFF auxiliary symbols exceed table")
    if len(names) != len(OWNED_NAMES) or set(names) != OWNED_NAMES:
        raise core.CorpusError(
            "selected object differs from the nine declared pesect functions"
        )


def validate_ownership(report: dict[str, Any], member_sha256: str) -> None:
    """Bind the collector's sole ownership input to the selected archive member."""
    count = report.get("library_object_count")
    hashes = report.get("library_object_sha256")
    if (
        type(count) is not int
        or count != 1
        or not isinstance(hashes, list)
        or hashes != [member_sha256]
    ):
        raise core.CorpusError(
            "pesect ownership requires exactly one object with the selected archive member SHA-256"
        )


def validate_truth(report: dict[str, Any]) -> None:
    """Retain the full predeclared translation-unit denominator, even if a smaller subset would pass."""
    if (
        set(report["library_truth"].values()) != OWNED_NAMES
        or report["truth_functions"] != 9
    ):
        raise core.CorpusError(
            "all nine predeclared pesect functions must remain in truth; no denominator dropping"
        )
    if (
        report.get("producer_range_source")
        != "explicit_identity_matched_pdb_procedures"
        or report.get("ownership_scope_id") != "public_strong"
    ):
        raise core.CorpusError(
            "pesect truth requires matched GLOBAL procedure ranges and public-strong ownership"
        )


def run(args: argparse.Namespace) -> dict[str, Any]:
    directory = core.prepare_output(args.output_dir)
    result: dict[str, Any] = {
        "schema_version": 1,
        "profile_id": "mingw-pesect-zig-0.17.0",
        "target": TARGET,
        "harness_optimization": args.optimization,
        "status": "failed",
        "passed": False,
        "source_class": "installedruntime",
        "target_executed": False,
    }
    commands = core.Commands(directory, clean_environment=True)
    try:
        zig = core.executable(args.zig)
        zig_sha = core.sha256(Path(zig))
        tools = directory / "tools"
        tools.mkdir()
        frozen = {
            name: core.freeze_measurement_tool(value, tools / name)
            for name, value in (("eval", args.evaluator), ("builder", args.builder))
        }
        result.update(
            tools=frozen,
            zig={"path": zig, "sha256": zig_sha},
            driver_sha256=core.sha256(Path(__file__)),
        )
        if commands.run([zig, "version"]).strip() != "0.17.0":
            raise core.UnsupportedProfile("pesect profile requires exact Zig 0.17.0")
        environment = commands.run([zig, "env"])
        roots = re.findall(r'^\s*\.lib_dir = ("[^"\n]+"),$', environment, re.MULTILINE)
        if len(roots) != 1:
            raise core.UnsupportedProfile(
                "expected one explicit Zig 0.17 installed library root"
            )
        sdk = Path(json.loads(roots[0])).resolve()
        for name, pin in SOURCE_PINS.items():
            data = core.archive_snapshot(sdk / name, pin)
            if name.endswith("pesect.c"):
                notice = data.split(b"*/", 1)[0] + b"*/"
                if hashlib.sha256(notice).hexdigest() != NOTICE_SHA256:
                    raise core.CorpusError("pesect source notice changed")
                result["source_notice"] = {
                    "text": notice.decode(),
                    "sha256": NOTICE_SHA256,
                }
        result.update(
            sdk_root=str(sdk),
            source_sha256=SOURCE_PINS,
            notice_sha256=NOTICE_SHA256,
            license_file={
                "path": str(sdk / "libc/mingw/COPYING"),
                "sha256": SOURCE_PINS["libc/mingw/COPYING"],
            },
            mingw_header_version="15.0.0 alpha; source release commit not established",
            ownership_scope="Exactly nine declared public-global pesect.c functions; not full CRT/Windows coverage",
            optimization_scope="Harness O1/O2 only; cached runtime object optimization is not inferred",
        )
        flags = [
            "-target",
            TARGET,
            f"-{args.optimization}",
            "-g",
            "-gcodeview",
            "-fno-lto",
            f"-ffile-prefix-map={directory}=.",
        ]
        for role in ("reference", "target"):
            source = ROOT / f"tests/fixtures/src/signature-mingw-pesect-{role}.c"
            result.setdefault("harness_sha256", {})[role] = core.sha256(source)
            commands.run(
                [
                    zig,
                    "cc",
                    *flags,
                    "-c",
                    str(source),
                    "-o",
                    str(directory / f"{role}.o"),
                ]
            )

        def link(role: str, objects: list[Path]) -> dict[str, Any]:
            program, pdb = directory / f"{role}.exe", directory / f"{role}.pdb"
            commands.run(
                [
                    zig,
                    "cc",
                    *flags,
                    "-static",
                    "-v",
                    "-Wl,--no-gc-sections",
                    *map(str, objects),
                    "-o",
                    str(program),
                ]
            )
            return core._replay_pe_link(commands, zig, program, pdb)

        probe = link("probe", [directory / "reference.o"])
        archives = [
            argument
            for argument in probe["replay"]["captured_linker_argv"]
            if Path(argument).name == "libmingw32.lib"
        ]
        if len(archives) != 1:
            raise core.CorpusError(
                "fresh Zig link must identify exactly one libmingw32.lib"
            )
        archive = (directory / archives[0]).resolve()
        if not archive.is_relative_to(directory / "zig-global-cache"):
            raise core.CorpusError(
                "runtime archive must originate in this fresh producer cache"
            )
        snapshot = core.archive_snapshot(archive, None)
        archive_sha = hashlib.sha256(snapshot).hexdigest()
        payload, member = select_member(snapshot)
        validate_object(payload)
        owned = directory / "pesect.o"
        with owned.open("xb") as stream:
            stream.write(payload)
        result["runtime_archive"] = {
            "path": str(archive),
            "sha256": archive_sha,
            "class": "generated-build-artifact",
            "selected_member": member,
        }
        for role in ("reference", "target"):
            again, _ = select_member(core.archive_snapshot(archive, archive_sha))
            if again != payload or core.sha256(owned) != member["sha256"]:
                raise core.CorpusError("runtime ownership bytes changed before link")
            result.setdefault("pdb_producer", {})[role] = link(
                role, [directory / f"{role}.o", owned]
            )
            core.inspect(
                commands, frozen["eval"]["path"], directory / f"{role}.exe", TARGET
            )
        stripped = directory / "target.stripped.exe"
        commands.run(
            [
                frozen["eval"]["path"],
                "strip-pe",
                str(directory / "target.exe"),
                str(stripped),
            ]
        )
        core.inspect(commands, frozen["eval"]["path"], stripped, TARGET, stripped=True)
        paths = {
            "reference_sha256": directory / "reference.exe",
            "symbolized_target_sha256": directory / "target.exe",
            "stripped_target_sha256": stripped,
            "reference_pdb_sha256": directory / "reference.pdb",
            "target_pdb_sha256": directory / "target.pdb",
            "database_sha256": directory / "db.json",
            "compressed_database_sha256": directory / "db.json.gz",
            "evaluator_binary_sha256": Path(frozen["builder"]["path"]),
        }
        argv = [
            frozen["builder"]["path"],
            "--object",
            str(owned),
            "--diagnostic-limit",
            "0",
        ]
        for option, name in (
            ("reference", "reference.exe"),
            ("target", "target.exe"),
            ("stripped", stripped.name),
            ("pdb", "reference.pdb"),
            ("target-pdb", "target.pdb"),
            ("output", "db.json"),
            ("report", "builder-report.json"),
        ):
            argv.extend([f"--{option}", str(directory / name)])
        commands.run(argv, allowed=(0, 1))
        code = commands.records[-1]["returncode"]
        report = json.loads((directory / "builder-report.json").read_text())
        result["builder_report"] = report
        core.validate_builder_report(report, TARGET, code, paths)
        validate_ownership(report, member["sha256"])
        validate_truth(report)
        if core.sha256(owned) != member["sha256"]:
            raise core.CorpusError("owned pesect bytes changed after production")
        for name, pin in SOURCE_PINS.items():
            core.archive_snapshot(sdk / name, pin)
        result.update(passed=report["passed"], truth_scope_valid=True)
        result["status"] = "measured" if report["passed"] else "measured_failed"
    except core.UnsupportedProfile as error:
        result.update(status="unsupported", reason=str(error))
    except (core.CorpusError, OSError, ValueError, KeyError, struct.error) as error:
        result["reason"] = str(error)
    finally:
        for tool in [
            *result.get("tools", {}).values(),
            *([result["zig"]] if "zig" in result else []),
        ]:
            try:
                if core.sha256(Path(tool["path"])) != tool["sha256"]:
                    result.update(
                        status="failed",
                        passed=False,
                        reason="producer tool identity drifted",
                    )
            except OSError as error:
                result.update(status="failed", passed=False, reason=str(error))
        core.write_json(directory / "result.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--optimization", choices=("O1", "O2"), default="O1")
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--eval", dest="evaluator", required=True)
    parser.add_argument("--builder", required=True)
    outcome = run(parser.parse_args())
    print(json.dumps(outcome, indent=2))
    raise SystemExit(0 if outcome["status"] == "measured" else 1)
