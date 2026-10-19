#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import os
import resource
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
SDK = Path("/opt/homebrew/opt/ghidra/libexec")
JDK = Path("/opt/homebrew/opt/openjdk/bin")
OUTPUT = ROOT / "tests/fixtures/sleigh"
RAW = ROOT / "target/phase4-1-oracle-first"
SOURCE = ROOT / "tools/sleigh-fixture/SleighOracle.java"
CLASSPATH = [
    "Framework/Utility/lib/Utility.jar",
    "Framework/Generic/lib/Generic.jar",
    "Framework/SoftwareModeling/lib/SoftwareModeling.jar",
    "Features/Base/lib/Base.jar",
    "Framework/Docking/lib/Docking.jar",
    "Framework/Project/lib/Project.jar",
    "Framework/DB/lib/DB.jar",
    "Framework/Gui/lib/Gui.jar",
    "Framework/FileSystem/lib/FileSystem.jar",
    "Framework/Graph/lib/Graph.jar",
    "Framework/Help/lib/javahelp-2.0.05.jar",
    "Framework/Generic/lib/gson-2.13.2.jar",
    "Framework/Generic/lib/jdom2-2.0.6.1.jar",
    "Framework/Generic/lib/commons-lang3-3.20.0.jar",
    "Framework/Generic/lib/commons-collections4-4.6.0.jar",
    "Framework/Generic/lib/guava-32.1.3-jre.jar",
    "Framework/Generic/lib/failureaccess-1.0.1.jar",
    "Framework/Generic/lib/log4j-api-2.26.1.jar",
    "Framework/Generic/lib/log4j-core-2.26.1.jar",
    "Framework/SoftwareModeling/lib/isorelax-20050913.jar",
    "Framework/SoftwareModeling/lib/msv-20050913.jar",
    "Framework/SoftwareModeling/lib/relaxngDatatype-20050913.jar",
    "Framework/SoftwareModeling/lib/xsdlib-20050913.jar",
    "Framework/SoftwareModeling/lib/antlr-runtime-3.5.2.jar",
]
OWNED_BYTES = {
    "msp430": "b01210440343fc233041304020440343145330418512004630400044b012",
    "avr8": "0e9408010000e1f708950ac00995099403950895fccf011000000b94ffff0e94",
    "6502": "201080a901d0f9604c19806c0020eaeae860d0ec4c00800220",
}
API_SOURCES = {
    "Framework/SoftwareModeling/lib/SoftwareModeling-src.zip": [
        "ghidra/program/model/address/Address.java",
        "ghidra/program/model/address/AddressSpace.java",
        "ghidra/program/model/address/AbstractAddressSpace.java",
        "ghidra/program/model/address/GenericAddress.java",
        "ghidra/program/model/address/GenericAddressSpace.java",
        "ghidra/program/model/mem/ByteMemBufferImpl.java",
        "ghidra/app/plugin/processors/sleigh/SleighLanguage.java",
        "ghidra/app/plugin/processors/sleigh/SleighLanguageProvider.java",
        "ghidra/program/disassemble/Disassembler.java",
        "ghidra/app/util/PseudoInstruction.java",
    ],
    "Features/Base/lib/Base-src.zip": [
        "ghidra/app/cmd/function/CreateFunctionCmd.java",
    ],
}


MIB = 1024 * 1024
FILE_CAP = 32 * MIB
JSON_CAP = 4 * MIB
LOG_CAP = 8 * MIB
SOURCE_MEMBER_CAP = MIB
EXPECTED_ORACLE_SHA256 = (
    "8a0cc76f88780d5bf0cb782b0f7e714c83dd5e8786f9d5d49722756f5ccfec48"
)
HISTORICAL_ATTEMPTS = ("attempt-jk6eeb8n", "attempt-llzq0p41")


@dataclass
class Budget:
    max_bytes: int = 128 * MIB
    max_files: int = 512
    used_bytes: int = 0
    used_files: int = 0
    read_bytes: int = 0
    decoded_bytes: int = 0

    def reserve(self, size: int) -> None:
        if (
            size < 0
            or size > self.max_bytes - self.used_bytes
            or self.used_files >= self.max_files
        ):
            raise ValueError("aggregate snapshot budget exceeded")
        self.used_bytes += size
        self.used_files += 1

    def read_limit(self, requested: int) -> int:
        return min(requested, self.max_bytes - self.read_bytes - self.decoded_bytes + 1)

    def account(self, size: int, *, decoded: bool = False) -> None:
        if size > self.max_bytes - self.read_bytes - self.decoded_bytes:
            raise ValueError("actual aggregate read/decode budget exceeded")
        if decoded:
            self.decoded_bytes += size
        else:
            self.read_bytes += size


class CountedReader:
    def __init__(self, stream: BinaryIO, cap: int, budget: Budget | None) -> None:
        self.stream = stream
        self.cap = cap
        self.budget = budget

    def read(self, size: int = -1) -> bytes:
        requested = self.cap + 1 if size < 0 else min(size, self.cap + 1)
        if self.budget is not None:
            requested = self.budget.read_limit(requested)
        data = self.stream.read(requested)
        if self.budget is not None:
            self.budget.account(len(data))
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.stream.seek(offset, whence)

    def tell(self) -> int:
        return self.stream.tell()

    def fileno(self) -> int:
        return self.stream.fileno()

    def seekable(self) -> bool:
        return self.stream.seekable()


def identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def revalidate(path: Path, descriptor: int, initial: dict[str, int]) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise ValueError(
            f"path missing or inaccessible after read: {path.name}"
        ) from error
    if not stat.S_ISREG(current.st_mode):
        raise ValueError(f"path is no longer a regular file: {path.name}")
    if identity(os.fstat(descriptor)) != initial or identity(current) != initial:
        raise ValueError(f"descriptor/path identity changed during read: {path.name}")


@contextmanager
def checked_file(
    path: Path, cap: int, budget: Budget | None = None
) -> Generator[BinaryIO, None, None]:
    if cap < 0:
        raise ValueError("negative file cap")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"not a regular file: {path.name}")
        if metadata.st_size > cap:
            raise ValueError(f"file exceeds pre-read cap: {path.name}")
        initial = identity(metadata)
        revalidate(path, descriptor, initial)
        if budget is not None:
            budget.reserve(metadata.st_size)
        try:
            yield cast(BinaryIO, CountedReader(stream, cap, budget))
        finally:
            revalidate(path, descriptor, initial)


def read_bounded(path: Path, cap: int, budget: Budget | None = None) -> bytes:
    with checked_file(path, cap, budget) as stream:
        data = stream.read(cap + 1)
        if len(data) > cap:
            raise ValueError(f"file grew beyond read cap: {path.name}")
        return data


def digest(
    path: Path, cap: int = FILE_CAP, budget: Budget | None = None
) -> dict[str, Any]:
    with checked_file(path, cap, budget) as stream:
        initial = identity(os.fstat(stream.fileno()))
        result = hashlib.sha256()
        size = 0
        while chunk := stream.read(min(65536, cap + 1 - size)):
            size += len(chunk)
            if size > cap:
                raise ValueError(f"file grew beyond digest cap: {path.name}")
            result.update(chunk)
        return {"bytes": size, "sha256": result.hexdigest(), "identity": initial}


def snapshot(files: dict[str, Path], budget: Budget) -> dict[str, Any]:
    result = {}
    for name, path in files.items():
        cap = FILE_CAP
        if name.startswith("source/") or path.suffix == ".asm":
            cap = MIB
        elif name.startswith("fixtures/"):
            cap = 128 if path.suffix == ".bin" else JSON_CAP
        result[name] = digest(path, cap=cap, budget=budget)
    return result


def source_members(path: Path, members: list[str], budget: Budget) -> dict[str, Any]:
    result = {}
    with checked_file(path, FILE_CAP, budget) as stream, ZipFile(stream) as archive:
        infos = archive.infolist()
        if len(infos) > 20000:
            raise ValueError("source archive entry count exceeds cap")
        seen = set()
        for info in infos:
            name = info.filename
            parts = PurePosixPath(name).parts
            if (
                name in seen
                or name.startswith("/")
                or "\\" in name
                or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))
                or not parts
            ):
                raise ValueError("duplicate or unsafe source archive member")
            seen.add(name)
        for member in members:
            info = archive.getinfo(member)
            mode = info.external_attr >> 16
            if (
                info.is_dir()
                or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                or info.file_size > SOURCE_MEMBER_CAP
            ):
                raise ValueError("source member exceeds pre-read cap or is not regular")
            budget.reserve(info.file_size)
            with archive.open(info) as source:
                data = source.read(SOURCE_MEMBER_CAP + 1)
            if len(data) > SOURCE_MEMBER_CAP or len(data) != info.file_size:
                raise ValueError("source member exceeds read cap or declared length")
            budget.account(len(data), decoded=True)
            result[member] = {
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
    return result


def class_inventory(directory: Path) -> dict[str, Any]:
    files: dict[str, Path] = {}
    pending = [directory]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 32:
            raise ValueError("compiled-class directory count exceeds cap")
        initial_directory = os.stat(current, follow_symlinks=False)
        if not stat.S_ISDIR(initial_directory.st_mode):
            raise ValueError("compiled-class root is not an owned regular directory")
        with os.scandir(current) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise ValueError("symlink in owned compiled-class directory")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False) and entry.name.endswith(
                    ".class"
                ):
                    path = Path(entry.path)
                    files[path.relative_to(directory).as_posix()] = path
                else:
                    raise ValueError("unexpected non-class compiler output")
                if len(pending) + len(files) > 32:
                    raise ValueError("compiled-class inventory count exceeds cap")
        final_directory = os.stat(current, follow_symlinks=False)
        if identity(final_directory) != identity(initial_directory):
            raise ValueError("compiled-class directory changed during inventory")
    budget = Budget(max_bytes=4 * MIB, max_files=32)
    return {
        name: digest(path, cap=MIB, budget=budget)
        for name, path in sorted(files.items())
    }


def verify_classes(directory: Path, before: dict[str, Any]) -> dict[str, Any]:
    after = class_inventory(directory)
    if after != before:
        raise ValueError("compiled host class inventory changed after execution")
    return after


def write_new_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def sanitize(value: str, stage: Path) -> str:
    for actual, label in [
        (str(stage), "$STAGE"),
        (str(ROOT), "$REPO"),
        (str(SDK), "$SDK"),
        (str(JDK), "$JDK_BIN"),
    ]:
        value = value.replace(actual, label)
    return value


def preserve_history() -> list[dict[str, Any]]:
    old_bytes = read_bounded(OUTPUT / "provenance.json", JSON_CAP)
    old = json.loads(old_bytes)
    if old.get("schema_version") != 1:
        raise ValueError(
            "historical receipt already migrated; no second controlled attempt authorized"
        )
    original = OUTPUT / "provenance-historical-original.json"
    with original.open("xb") as output:
        output.write(old_bytes)
    history = []
    for attempt in HISTORICAL_ATTEMPTS:
        directory = RAW / attempt
        before = json.loads(read_bounded(directory / "before.json", JSON_CAP))
        after = json.loads(read_bounded(directory / "after.json", JSON_CAP))
        commands = json.loads(read_bounded(directory / "commands.json", JSON_CAP))
        result = digest(directory / "oracle.json", JSON_CAP)
        if result["sha256"] != EXPECTED_ORACLE_SHA256:
            raise ValueError("historical oracle differs from frozen oracle")
        record = {
            "schema_version": 2,
            "kind": "historical_receipt_repackaged_during_p2_audit",
            "attempt": attempt,
            "inputs_before": before,
            "inputs_after": after,
            "commands": json.loads(sanitize(json.dumps(commands), directory)),
            "oracle_result_sha256": result["sha256"],
            "compiled_class_binding": "missing: compiled classes were not hashed and stage was deleted",
            "retroactive_class_attestation": False,
            "scope": "Existing raw records only; current source and class hashes do not attest this historical run.",
            "raw_receipts": f"$REPO/target/phase4-1-oracle-first/{attempt}",
        }
        name = f"provenance-historical-{attempt}.json"
        write_new_json(OUTPUT / name, record)
        history.append(
            {
                "path": name,
                "sha256": digest(OUTPUT / name, JSON_CAP)["sha256"],
                "attempt": attempt,
                "compiled_class_binding": "missing",
                "tool_source_sha256": before["source/run_oracle.py"]["sha256"],
            }
        )
    history.append(
        {
            "path": original.name,
            "sha256": hashlib.sha256(old_bytes).hexdigest(),
            "kind": "byte_identical_original_public_receipt",
            "compiled_class_binding": "missing",
        }
    )
    return history


def limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    os.umask(0o077)


def run() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)
    frozen = read_bounded(OUTPUT / "oracle.json", JSON_CAP)
    if hashlib.sha256(frozen).hexdigest() != EXPECTED_ORACLE_SHA256:
        raise ValueError("frozen oracle does not match the reviewed historical result")
    for name, value in OWNED_BYTES.items():
        path = OUTPUT / f"{name}.bin"
        data = bytes.fromhex(value)
        if read_bounded(path, 128) != data:
            raise ValueError(f"frozen owned fixture differs: {name}")
    historical = preserve_history()
    raw = Path(tempfile.mkdtemp(prefix="attempt-p2-", dir=RAW))
    files = {
        "source/SleighOracle.java": SOURCE,
        "source/run_oracle.py": Path(__file__).resolve(),
        "source/test_run_oracle.py": ROOT / "tools/sleigh-fixture/test_run_oracle.py",
    }
    files.update({f"sdk/Ghidra/{name}": SDK / "Ghidra" / name for name in CLASSPATH})
    files["sdk/Ghidra/application.properties"] = SDK / "Ghidra/application.properties"
    files["sdk/LICENSE"] = SDK / "LICENSE"
    for archive in API_SOURCES:
        files[f"sdk/Ghidra/{archive}"] = SDK / "Ghidra" / archive
    for module in ("6502", "Atmel", "TI_MSP430"):
        directory = SDK / "Ghidra/Processors" / module / "data/languages"
        for path in sorted(directory.iterdir()):
            if path.is_file():
                files[f"sdk/{path.relative_to(SDK)}"] = path
    for name in OWNED_BYTES:
        files[f"fixtures/{name}.bin"] = OUTPUT / f"{name}.bin"
        files[f"fixtures/{name}.asm"] = OUTPUT / f"{name}.asm"
    files["fixtures/truth.json"] = OUTPUT / "truth.json"
    files["fixtures/oracle.json"] = OUTPUT / "oracle.json"
    launchers = {
        name: (JDK / name).resolve(strict=True) for name in ("java", "javac", "javap")
    }
    for name, path in launchers.items():
        files[f"jdk/bin/{name}"] = path
    budget = Budget()
    before = snapshot(files, budget)
    properties_key = "sdk/Ghidra/application.properties"
    if (
        before[properties_key]["sha256"]
        != "19a74006a0351da7da1a8ee00ea0e864e672b1cb0c6e7132cdd210c9d672868c"
    ):
        raise ValueError("unexpected installed Ghidra application.properties")
    member_receipts = {}
    for archive, selected_members in API_SOURCES.items():
        for member, receipt in source_members(
            SDK / "Ghidra" / archive, selected_members, budget
        ).items():
            member_receipts[f"{archive}!/{member}"] = receipt
    write_new_json(raw / "before.json", before)
    stage = Path(tempfile.mkdtemp(prefix="sleigh-owned-", dir=raw))
    commands: list[dict[str, Any]] = []
    result_path = stage / "oracle.json"
    result_bytes: bytes | None = None
    classes_before: dict[str, Any] = {}
    classes_after: dict[str, Any] = {}
    result_state: dict[str, Any] = {"failure": None}
    try:
        home = stage / "home"
        temp = stage / "tmp"
        home.mkdir()
        temp.mkdir()
        classes = stage / "classes"
        classes.mkdir()
        environment = {
            "HOME": str(home),
            "TMPDIR": str(temp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": str(JDK),
        }
        classpath = os.pathsep.join(str(SDK / "Ghidra" / name) for name in CLASSPATH)
        invocations = [
            ("jdk-version", [str(launchers["java"]), "-version"]),
            (
                "api-signatures",
                [
                    str(launchers["javap"]),
                    "-classpath",
                    classpath,
                    "ghidra.program.model.address.Address",
                    "ghidra.program.model.address.AddressSpace",
                    "ghidra.program.model.lang.Language",
                    "ghidra.program.model.lang.InstructionPrototype",
                    "ghidra.app.util.PseudoInstruction",
                    "ghidra.program.disassemble.Disassembler",
                    "ghidra.app.cmd.function.CreateFunctionCmd",
                ],
            ),
            (
                "compile",
                [
                    str(launchers["javac"]),
                    "-cp",
                    classpath,
                    "-d",
                    str(classes),
                    str(SOURCE),
                ],
            ),
            (
                "oracle",
                [
                    str(launchers["java"]),
                    "-Xmx512m",
                    "-Djava.awt.headless=true",
                    f"-Duser.home={home}",
                    f"-Djava.io.tmpdir={temp}",
                    "-cp",
                    os.pathsep.join((str(classes), classpath)),
                    "SleighOracle",
                    str(OUTPUT),
                    str(result_path),
                ],
            ),
        ]
        for name, command in invocations:
            receipt: dict[str, Any] = {
                "name": name,
                "argv": command,
                "status": "starting",
            }
            if name == "oracle":
                classes_before = class_inventory(classes)
                if "SleighOracle.class" not in classes_before:
                    raise ValueError("required compiled host entry class missing")
                receipt["compiled_classes_before_launch"] = classes_before
            commands.append(receipt)
            (raw / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            with (
                (raw / f"{name}.stdout").open("xb") as stdout,
                (raw / f"{name}.stderr").open("xb") as stderr,
            ):
                try:
                    completed = subprocess.run(
                        command,
                        cwd=stage,
                        env=environment,
                        stdout=stdout,
                        stderr=stderr,
                        timeout=120,
                        check=False,
                        preexec_fn=limits,
                    )
                except subprocess.TimeoutExpired as error:
                    receipt["status"] = "timeout"
                    raise RuntimeError(
                        f"{name} exceeded the 120-second host deadline"
                    ) from error
                finally:
                    if name == "oracle":
                        classes_after = class_inventory(classes)
                        receipt["compiled_classes_after_execution"] = classes_after
                        receipt["compiled_classes_unchanged"] = (
                            classes_before == classes_after
                        )
                    (raw / "commands.json").write_text(
                        json.dumps(commands, indent=2) + "\n"
                    )
            receipt.update({"exit_code": completed.returncode, "status": "exited"})
            if completed.returncode != 0:
                raise RuntimeError(
                    f"{name} failed; see {raw.relative_to(ROOT)}/{name}.stderr"
                )
            if name == "oracle":
                verify_classes(classes, classes_before)
        data = read_bounded(result_path, JSON_CAP)
        (raw / "oracle.json").write_bytes(data)
        if data != frozen:
            raise ValueError(
                "new oracle differs from frozen gold; raw result retained, gold not replaced"
            )
        result_bytes = data
    except Exception as error:
        result_state["failure"] = sanitize(f"{type(error).__name__}: {error}", stage)
        raise
    finally:
        after_budget = Budget()
        try:
            after = snapshot(files, after_budget)
        finally:
            shutil.rmtree(stage)
        write_new_json(raw / "after.json", after)
        (raw / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        public_commands = json.loads(sanitize(json.dumps(commands), stage))
        logs = {
            path.name: sanitize(
                read_bounded(path, LOG_CAP).decode(errors="replace"), stage
            )
            for path in sorted(raw.glob("*.std*"))
        }
        provenance = {
            "schema_version": 2,
            "kind": "current_controlled_p2_receipt",
            "attempt": raw.name,
            "capture_date": "2026-10-19",
            "network_used": False,
            "commands": public_commands,
            "logs": logs,
            "inputs_before": before,
            "inputs_after": after,
            "unchanged": before == after,
            "api_source_archive_members": member_receipts,
            "compiled_classes_before_launch": classes_before,
            "compiled_classes_after_execution": classes_after,
            "compiled_classes_unchanged": bool(classes_before)
            and classes_before == classes_after,
            "compiled_class_scope": "Owned javac host output only, not an SDK plugin or target executable",
            "failure": result_state["failure"],
            "status": "success"
            if result_bytes is not None and before == after
            else "failed",
            "oracle_result_sha256": hashlib.sha256(result_bytes).hexdigest()
            if result_bytes
            else None,
            "stage_removed_after_exit": True,
            "limits": {
                "instruction_bytes": 32,
                "pcode_ops_per_instruction": 128,
                "text_chars_per_operation": 512,
                "fixture_bytes": 128,
                "parser_window_bytes": 65536,
                "process_timeout_seconds": 120,
                "regular_file_pre_read_bytes": FILE_CAP,
                "snapshot_aggregate_bytes_per_pass": 128 * MIB,
                "snapshot_files_per_pass": 512,
                "before_budget_includes_source_archives_and_member_reads": True,
                "before_budget_reserved_bytes": budget.used_bytes,
                "before_actual_file_read_bytes": budget.read_bytes,
                "before_actual_decoded_member_bytes": budget.decoded_bytes,
                "after_budget_reserved_bytes": after_budget.used_bytes,
                "after_actual_file_read_bytes": after_budget.read_bytes,
                "owned_tool_source_pre_read_bytes": MIB,
                "aggregate_cap_reason": (
                    "The fixed trusted SDK jars plus source archives alone total 55,297,066 bytes; "
                    "128 MiB bounds each snapshot pass including source archive inspection/member reservations. "
                    "This is not a 32 MiB total claim and does not change processor-admission source budgets."
                ),
                "source_member_pre_read_bytes": SOURCE_MEMBER_CAP,
                "compiled_class_file_bytes": MIB,
                "compiled_classes_aggregate_bytes": 4 * MIB,
                "compiled_classes_count": 32,
                "json_pre_read_bytes": JSON_CAP,
                "stdout_stderr_each_os_and_read_bytes": LOG_CAP,
            },
            "authentication_limit": "Installed-byte hashes are not SDK archive or upstream-commit authentication.",
            "scope": "Static Java Sleigh parse and raw pcode only. No target execution or decompilation.",
            "analyzers": "No analysis manager or automatic analyzers scheduled; no loader or library import.",
            "classpath_policy": "Fixed installed framework/Base jars and explicit third-party dependencies only.",
            "source_policy": "Installed ordinary SLASPEC/SINC files hashed, not compiled by this oracle.",
            "profile_policy": "Only three hardcoded language/compiler pairs selected; siblings not admitted.",
            "source_repository": "https://github.com/NationalSecurityAgency/ghidra",
            "source_tag": "Ghidra_12.1.4_build",
            "resolved_source_commit": None,
            "sdk_archive_sha256": None,
            "snapshot_policy": "Installed language-directory snapshots include unselected siblings; not an I/O trace.",
            "producer_read_binding": (
                "Python producer uses O_NOFOLLOW/O_NONBLOCK regular descriptors; "
                "fstat/path identities checked before and after reads. "
                "Identity includes device/inode/size/mtime/ctime, not atime. "
                "This is interval observation, not a filesystem lock or proof against adversarial restore races."
            ),
            "runtime_limit": (
                "JDK launcher hashes and version pin the host observation, not every dynamic runtime library."
            ),
            "address_api_facts": [
                "AddressSpace.getAddressableWordOffset(long byteOffset) documents its input as memory bytes.",
                "GenericAddress.getAddressableWordOffset delegates using its stored getOffset value.",
                "Code targets preserve both actual Java getters; no inferred multiplication is serialized.",
                "Constant-space varnodes are scalar values/local pcode indices, not memory byte addresses.",
            ],
        }
        public_name = f"provenance-{raw.name}.json"
        write_new_json(raw / "receipt.json", provenance)
        write_new_json(OUTPUT / public_name, provenance)
        index = {
            "schema_version": 2,
            "kind": "historical_and_current_receipt_index",
            "historical_receipts": historical,
            "historical_binding_limit": (
                "Both previous final runs lack compiled-class hashes. Their before/after records remain historical; "
                "the new class binding does not retroactively attest them."
            ),
            "current_receipt": {
                "path": public_name,
                "sha256": digest(OUTPUT / public_name, FILE_CAP)["sha256"],
                "attempt": raw.name,
                "status": provenance["status"],
            },
            "frozen_oracle_sha256": EXPECTED_ORACLE_SHA256,
            "claim_limit": "Static Ghidra oracle facts passed; not CPU semantic authentication.",
        }
        (OUTPUT / "provenance.json").write_text(json.dumps(index, indent=2) + "\n")
        if before != after:
            raise RuntimeError("oracle snapshot changed; result is not accepted")
    print(f"Controlled attempt: {raw.relative_to(ROOT)}")


if __name__ == "__main__":
    run()
