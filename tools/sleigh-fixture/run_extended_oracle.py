#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

SPEC = importlib.util.spec_from_file_location(
    "owned_pilot_io", Path(__file__).with_name("run_oracle.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("fixed owned IO helper unavailable")
io = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = io
SPEC.loader.exec_module(io)
ROOT = io.ROOT
OUTPUT = ROOT / "tests/fixtures/sleigh/extended"
RAW = ROOT / "target/phase4-1-oracle-extended-first"
PLAN = ROOT / "target/phase4-1-oracle-next-first/next-13-plan.json"
MANIFEST = ROOT / "crates/rampage-decompiler/specs/processor-admission.json"
PLAN_SHA = "d891f390c535002c4e4d33c95f00b7ff9ba13aebfb562240c676fdb5d5b246b5"
MANIFEST_SHA = "c7e5f028dc7816cf6d895cd4e72db18292175c2e47b7c61f82a461250fe9f384"
NAMES = (
    "8051",
    "PIC",
    "SuperH",
    "V850",
    "TriCore",
    "Xtensa",
    "Z80",
    "HCS12",
    "6805",
    "CR16",
    "eBPF",
    "Loongarch",
    "Hexagon",
)
MAIN_END = dict(zip(NAMES, (7, 10, 10, 10, 8, 11, 7, 6, 7, 10, 32, 16, 16)))
CALL_OFFSET = dict.fromkeys(NAMES, 0)
BRANCH_OFFSET = dict(zip(NAMES, (4, 4, 4, 6, 4, 6, 4, 3, 4, 6, 16, 8, 8)))
RETURN_OFFSET = dict(zip(NAMES, (6, 8, 6, 8, 6, 9, 6, 5, 6, 8, 24, 12, 12)))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_json(path: Path, expected: str) -> dict[str, Any]:
    data = io.read_bounded(path, io.JSON_CAP)
    if sha(data) != expected:
        raise ValueError(f"fixed release/plan pin differs: {path.name}")
    return json.loads(data)


def snapshot(files: dict[str, Path], budget: Any) -> dict[str, Any]:
    result = {}
    for name, path in files.items():
        cap = io.FILE_CAP
        if path.suffix == ".json":
            cap = io.JSON_CAP
        elif path.suffix == ".bin":
            cap = 128
        elif name.startswith("source/") or path.suffix == ".asm":
            cap = io.MIB
        result[name] = io.digest(path, cap, budget)
    return result


def materialize(plan: dict[str, Any]) -> list[dict[str, Any]]:
    if tuple(row["family"] for row in plan["profiles"]) != NAMES:
        raise ValueError("fixed profile selection differs")
    OUTPUT.mkdir(exist_ok=False)
    truth = []
    for row in plan["profiles"]:
        name = row["family"]
        key = name + "-v1"
        data = bytes.fromhex(row["bytes_hex"])
        if not 0 < len(data) <= 128:
            raise ValueError("owned fixture exceeds byte cap")
        with (OUTPUT / f"{key}.bin").open("xb") as output:
            output.write(data)
        lines = [
            "; SPDX-License-Identifier: Apache-2.0",
            "; Hand-owned explanatory encoding ledger, not assembler output.",
            f"; {row['language_id']} / default; all left-column offsets are bytes.",
            f"; Byte base {row['planned_base_byte_offset']}; static host analysis only; no target execution.",
        ]
        for instruction in row["instruction_ledger"]:
            lines.append(
                f"{instruction['offset_bytes']:04x}  {instruction['bytes_hex']}  "
                + instruction["owned_explanatory_asm"]
            )
        lines.extend(
            "; " + limit for limit in row["spaces_packet_delay_and_semantic_limits"]
        )
        with (OUTPUT / f"{key}.asm").open("x") as output:
            output.write("\n".join(lines) + "\n")
        functions = [
            {"name": "main", "start_bytes": 0, "end_exclusive_bytes": MAIN_END[name]},
            {
                "name": "callee",
                "start_bytes": row["planned_callee_offset_bytes"],
                "end_exclusive_bytes": len(data),
            },
        ]
        entry = {
            "name": key,
            "family": name,
            "version": 1,
            "language_id": row["language_id"],
            "compiler_spec_id": "default",
            "base_byte_offset": row["planned_base_byte_offset"],
            "byte_length": len(data),
            "input_sha256": sha(data),
            "functions": functions,
            "instruction_ledger": row["instruction_ledger"],
            "call_offset_bytes": CALL_OFFSET[name],
            "conditional_offset_bytes": BRANCH_OFFSET[name],
            "return_offset_bytes": RETURN_OFFSET[name],
            "constructor_references": row["constructor_references"],
            "limits": row["spaces_packet_delay_and_semantic_limits"],
            "call_target_policy": "context_dependent_computed_PCLATH"
            if name == "PIC"
            else "direct_owned_callee",
            "conditional_policy": "flowed_skip_context_on_following_instruction"
            if name == "PIC"
            else "conditional_jump",
            "c_model_and_abi": "unknown_not_authenticated",
            "cpu_boundary": "SDK selection only, no CPU execution",
            "function_truth_origin": "manual hand-owned source extent frozen before ProgramDB creation",
            "function_bound_policy": "Half-open byte ranges; SuperH includes intrinsic return/call delay slots; "
            "Hexagon consists only of complete one-word packets.",
        }
        io.write_new_json(OUTPUT / f"{key}.truth.json", entry)
        truth.append(entry)
    io.write_new_json(
        OUTPUT / "truth.json",
        {
            "schema_version": 1,
            "fixtures": truth,
            "origin": "owned source/reference, never Rust output",
        },
    )
    return truth


def validate(actual: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    failures = []
    program = actual.get("program_oracle", {})
    if program.get("status") != "observed":
        return {
            "status": "technical_failure",
            "failures": [program.get("error", "program oracle absent")],
            "manual_true_functions": 2,
            "observed_function_count": program.get("observed_function_count"),
        }
    rows = {row["fixture_offset_bytes"]: row for row in program["rows"]}
    for intended in truth["instruction_ledger"]:
        offset = intended["offset_bytes"]
        row = rows.get(offset)
        if row is None or row.get("status") != "decoded":
            failures.append(f"instruction at byte {offset}: missing/technical failure")
            continue
        if row["length_bytes"] != len(bytes.fromhex(intended["bytes_hex"])):
            failures.append(f"instruction at byte {offset}: length mismatch")
        expected = (
            intended["owned_explanatory_asm"]
            .split(";")[0]
            .replace("callee:", "")
            .strip()
        )
        if truth["family"] == "Hexagon":
            expected = (
                "jump"
                if "IF (p0)" in expected
                else expected.replace("{", "").strip().split()[0]
            )
            mnemonic_ok = row["mnemonic"].lower().startswith(expected.lower())
        else:
            mnemonic_ok = row["mnemonic"].upper() == expected.split()[0].upper()
        if not mnemonic_ok:
            failures.append(
                f"instruction at byte {offset}: expected {expected.split()[0]}, observed {row['mnemonic']}"
            )
        if "pcode_error" in row:
            failures.append(f"instruction at byte {offset}: {row['pcode_error']}")
    call = rows.get(truth["call_offset_bytes"], {})
    if not call.get("flow", {}).get("is_call"):
        failures.append("manual call is not classified as call")
    if truth["call_target_policy"] == "direct_owned_callee":
        target = (
            int(truth["base_byte_offset"], 16) + truth["functions"][1]["start_bytes"]
        )
        targets = call.get("direct_flow_targets", [])
        if not any(int(item["getOffset_bytes"], 16) == target for item in targets):
            failures.append("owned direct callee target missing/wrong")
    branch = rows.get(truth["conditional_offset_bytes"], {})
    if truth["family"] == "PIC":
        following = rows.get(truth["conditional_offset_bytes"] + 2, {})
        if not any(
            op["mnemonic"] == "CBRANCH" for op in following.get("raw_pcode", [])
        ):
            failures.append(
                "PIC flowed skip condition absent from following instruction pcode"
            )
    elif not branch.get("flow", {}).get("is_conditional"):
        failures.append("manual conditional not classified conditional")
    ret = rows.get(truth["return_offset_bytes"], {})
    if not ret.get("flow", {}).get("is_terminal"):
        failures.append("manual return not classified terminal")
    base = int(truth["base_byte_offset"], 16)
    functions = program.get("functions", [])
    for wanted in truth["functions"]:
        observed = next(
            (
                item
                for item in functions
                if item["manual_seed_offset_bytes"] == wanted["start_bytes"]
            ),
            {},
        )
        ranges = observed.get("body_ranges", [])
        wanted_range = (
            base + wanted["start_bytes"],
            base + wanted["end_exclusive_bytes"],
        )
        actual_ranges = [
            (
                int(item["start"]["getOffset_bytes"], 16),
                int(item["end_inclusive"]["getOffset_bytes"], 16) + 1,
            )
            for item in ranges
        ]
        if actual_ranges != [wanted_range]:
            failures.append(
                f"manual function {wanted['name']} extent differs: {actual_ranges}"
            )
    created_starts = [
        item["manual_seed_offset_bytes"]
        for item in functions
        if item.get("status") == "created"
    ]
    return {
        "status": "pass" if not failures else "mismatch",
        "failures": failures,
        "manual_true_functions": 2,
        "observed_function_count": program["observed_function_count"],
        "true_positive_seeded_entries": len(created_starts),
        "unseeded_function_count": program["observed_function_count"]
        - len(created_starts),
        "missing_seeded_entries": 2 - len(created_starts),
        "padding_instruction_count": program["padding_instruction_count"],
        "measurement_limit": "Seeded Ghidra function creation, not autonomous discovery or CPU semantic proof",
    }


def command_run(
    command: list[str], stage: Path, raw: Path, name: str
) -> dict[str, Any]:
    home, temp = stage / "home", stage / "tmp"
    home.mkdir(exist_ok=True)
    temp.mkdir(exist_ok=True)
    receipt: dict[str, Any] = {"argv": command, "name": name, "timeout_seconds": 120}
    with (
        (raw / f"{name}.stdout").open("xb") as out,
        (raw / f"{name}.stderr").open("xb") as err,
    ):
        try:
            result = subprocess.run(
                command,
                cwd=stage,
                env={
                    "HOME": str(home),
                    "TMPDIR": str(temp),
                    "PATH": str(io.JDK),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                stdout=out,
                stderr=err,
                check=False,
                timeout=120,
                preexec_fn=io.limits,
            )
            receipt["exit_code"] = result.returncode
        except subprocess.TimeoutExpired:
            receipt["status"] = "timeout"
    return receipt


def remove_owned_directory(
    parent_fd: int, name: str, expected: tuple[int, int]
) -> None:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=parent_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != expected:
            raise ValueError("owned stage directory identity changed; cleanup refused")
        with os.scandir(descriptor) as entries:
            names = [entry.name for entry in entries]
        for child in names:
            metadata = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                remove_owned_directory(
                    descriptor, child, (metadata.st_dev, metadata.st_ino)
                )
            else:
                os.unlink(child, dir_fd=descriptor)
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != expected or not stat.S_ISDIR(
            metadata.st_mode
        ):
            raise ValueError("owned stage root changed before removal; cleanup refused")
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        os.close(descriptor)


@contextmanager
def owned_stage(parent: Path, name: str) -> Generator[Path, None, None]:
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError("stage must be a fixed child directory name")
    parent_fd = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        expected = None
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            expected = (metadata.st_dev, metadata.st_ino)
            yield parent / name
        finally:
            if expected is None:
                os.rmdir(name, dir_fd=parent_fd)
            else:
                remove_owned_directory(parent_fd, name, expected)
    finally:
        os.close(parent_fd)


def run() -> None:
    plan = pinned_json(PLAN, PLAN_SHA)
    manifest = pinned_json(MANIFEST, MANIFEST_SHA)
    if len(manifest["profiles"]) != 16:
        raise ValueError("released resource manifest differs")
    truth = materialize(plan)
    RAW.mkdir(exist_ok=True)
    cohort = Path(tempfile.mkdtemp(prefix="cohort-v1-", dir=RAW))
    with ExitStack() as stages:
        run_cohort(plan, manifest, truth, cohort, stages)


def run_cohort(
    plan: dict[str, Any],
    manifest: dict[str, Any],
    truth: list[dict[str, Any]],
    cohort: Path,
    stages: ExitStack,
) -> None:
    compile_stage = stages.enter_context(owned_stage(cohort, "compile-stage"))
    classes = compile_stage / "classes"
    classes.mkdir()
    classpath = os.pathsep.join(str(io.SDK / "Ghidra" / item) for item in io.CLASSPATH)
    launchers = {
        name: (io.JDK / name).resolve(strict=True)
        for name in ("java", "javac", "javap")
    }
    common = {
        "source/" + name: ROOT / "tools/sleigh-fixture" / name
        for name in (
            "SleighOracle.java",
            "run_oracle.py",
            "ExtendedSleighOracle.java",
            "run_extended_oracle.py",
            "test_run_extended_oracle.py",
            "test_stage_cleanup.py",
        )
    }
    common.update(
        {
            "sdk/Ghidra/" + name: io.SDK / "Ghidra" / name
            for name in io.CLASSPATH + list(io.API_SOURCES)
        }
    )
    common.update({"jdk/bin/" + name: path for name, path in launchers.items()})
    common.update(
        {
            "fixtures/cohort-truth.json": OUTPUT / "truth.json",
            "inputs/plan.json": PLAN,
            "inputs/admission.json": MANIFEST,
            "source/admit-processor-specs.py": ROOT / "tools/admit-processor-specs.py",
            "sdk/Ghidra/application.properties": io.SDK
            / "Ghidra/application.properties",
        }
    )
    compilation_before = snapshot(common, io.Budget())
    io.write_new_json(cohort / "compile-before.json", compilation_before)
    source_snapshots = cohort / "source-tool-snapshot"
    source_snapshots.mkdir()
    for name, path in common.items():
        if name.startswith("source/"):
            data = io.read_bounded(path, io.MIB)
            if sha(data) != compilation_before[name]["sha256"]:
                raise ValueError("source snapshot changed before compilation")
            with (source_snapshots / path.name).open("xb") as output:
                output.write(data)
    compile_receipt = command_run(
        [
            str(launchers["javac"]),
            "-cp",
            classpath,
            "-d",
            str(classes),
            str(common["source/SleighOracle.java"]),
            str(common["source/ExtendedSleighOracle.java"]),
        ],
        classes.parent,
        cohort,
        "compile",
    )
    io.write_new_json(cohort / "compile-command.json", compile_receipt)
    if compile_receipt.get("exit_code") != 0:
        raise RuntimeError(
            f"owned helper compilation failed; {cohort.relative_to(ROOT)}"
        )
    compiled = io.class_inventory(classes)
    io.write_new_json(cohort / "classes-after-compile.json", compiled)
    if snapshot(common, io.Budget()) != compilation_before:
        raise RuntimeError("compile source/SDK inputs changed")
    results: list[dict[str, Any]] = []
    try:
        for wanted in truth:
            key = wanted["name"]
            raw = Path(tempfile.mkdtemp(prefix=key + "-attempt-", dir=cohort))
            profile_stages = stages.enter_context(ExitStack())
            stage = profile_stages.enter_context(owned_stage(raw, "stage"))
            selected = next(
                item
                for item in manifest["profiles"]
                if item["family"] == wanted["family"]
            )
            if (
                selected["language_id"] != wanted["language_id"]
                or selected["compiler_id"] != "default"
            ):
                raise ValueError("released selected pair differs")
            files = dict(common)
            for suffix in ("bin", "asm", "truth.json"):
                files[f"fixtures/{key}.{suffix}"] = OUTPUT / f"{key}.{suffix}"
            module = plan["profiles"][NAMES.index(wanted["family"])][
                "selected_sdk_metadata"
            ]
            language_dir = io.SDK / Path(selected["sla_path"]).parent
            for path in sorted(language_dir.iterdir()):
                if path.suffix in {
                    ".sla",
                    ".pspec",
                    ".cspec",
                    ".ldefs",
                    ".sinc",
                    ".slaspec",
                }:
                    files["sdk/" + str(path.relative_to(io.SDK))] = path
            budget = io.Budget()
            before = snapshot(files, budget)
            for field in ("sla_path", "pspec_path", "cspec_path", "ldefs_path"):
                admitted = next(
                    item
                    for item in manifest["files"]
                    if item["path"] == selected[field]
                )
                if before["sdk/" + selected[field]]["sha256"] != admitted["sha256"]:
                    raise ValueError(
                        "installed selected SDK resource differs from released bytes"
                    )
            if io.class_inventory(classes) != compiled:
                raise ValueError("compiled class tree changed before profile launch")
            io.write_new_json(raw / "before.json", before)
            cmd = [
                str(launchers["java"]),
                "-Xmx512m",
                "-Djava.awt.headless=true",
                f"-Duser.home={stage / 'home'}",
                f"-Djava.io.tmpdir={stage / 'tmp'}",
                "-cp",
                os.pathsep.join((str(classes), classpath)),
                "ExtendedSleighOracle",
                key,
                str(OUTPUT),
                str(raw / "oracle.json"),
            ]
            command: dict[str, Any] = {
                "argv": cmd,
                "compiled_classes_before_launch": compiled,
                "status": "starting",
            }
            io.write_new_json(raw / "command-before-launch.json", command)
            actual: dict[str, Any] = {}
            try:
                command.update(command_run(cmd, stage, raw, "oracle"))
                command["compiled_classes_after_execution"] = io.class_inventory(
                    classes
                )
                command["compiled_classes_unchanged"] = (
                    command["compiled_classes_after_execution"] == compiled
                )
                if not command["compiled_classes_unchanged"]:
                    raise ValueError("compiled class binding changed")
                if command.get("exit_code") == 0:
                    actual = json.loads(
                        io.read_bounded(raw / "oracle.json", io.JSON_CAP)
                    )
                else:
                    actual = {
                        "fixture": key,
                        "program_oracle": {
                            "status": "technical_failure",
                            "error": "Java process failed or timed out; full bounded stderr retained",
                        },
                    }
                verdict = validate(actual, wanted)
            except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
                verdict = {
                    "status": "technical_failure",
                    "failures": [f"{type(error).__name__}: {error}"],
                }
                actual = actual or {
                    "fixture": key,
                    "program_oracle": {
                        "status": "technical_failure",
                        "error": "Host oracle/receipt processing failed; original logs retained",
                    },
                }
            finally:
                after_budget = io.Budget()
                try:
                    after = snapshot(files, after_budget)
                finally:
                    profile_stages.close()
                io.write_new_json(raw / "after.json", after)
                io.write_new_json(raw / "command.json", command)
            if before != after:
                verdict = {
                    "status": "technical_failure",
                    "failures": ["source/SDK/fixture snapshot changed"],
                }
            result = {
                "name": key,
                "family": wanted["family"],
                "language_id": wanted["language_id"],
                "verdict": verdict,
                "oracle": actual,
            }
            io.write_new_json(OUTPUT / f"{key}.oracle.json", result)
            receipt = {
                "schema_version": 1,
                "attempt": raw.name,
                "capture_date": "2026-10-19",
                "kind": "extended_independent_static_java_oracle",
                "fixture": key,
                "verdict": verdict,
                "inputs_before": before,
                "inputs_after": after,
                "unchanged": before == after,
                "command": json.loads(io.sanitize(json.dumps(command), stage)),
                "logs": {
                    path.name: io.sanitize(
                        io.read_bounded(path, io.LOG_CAP).decode(errors="replace"),
                        stage,
                    )
                    for path in sorted(raw.glob("oracle.std*"))
                },
                "oracle_sha256": io.digest(raw / "oracle.json", io.JSON_CAP)["sha256"]
                if (raw / "oracle.json").exists()
                else None,
                "planning_source_binding": {
                    "kind": "historical_planning_hash_not_current_helper_attestation",
                    **plan["selected_profiles_source"],
                },
                "current_admission_helper_sha256": before[
                    "source/admit-processor-specs.py"
                ]["sha256"],
                "released_manifest_sha256": MANIFEST_SHA,
                "limits": {
                    "file_pre_read_bytes": io.FILE_CAP,
                    "snapshot_aggregate_bytes_per_pass": budget.max_bytes,
                    "snapshot_reason": "Trusted fixed jars/source archives exceed 32 MiB total; per-file cap remains 32 MiB",
                    "before_reserved_bytes": budget.used_bytes,
                    "before_actual_read_bytes": budget.read_bytes,
                    "after_actual_read_bytes": after_budget.read_bytes,
                    "fixture_bytes": 128,
                    "result_json_bytes": io.JSON_CAP,
                    "class_file_bytes": io.MIB,
                    "class_inventory_aggregate_bytes": 4 * io.MIB,
                    "class_count": 32,
                    "instruction_bytes": 32,
                    "pcode_ops": 128,
                    "operation_text_chars": 512,
                    "stdout_stderr_each_bytes": io.LOG_CAP,
                    "process_seconds": 120,
                },
                "stage_removed": True,
                "target_execution": False,
                "network": False,
                "claim_limit": "SDK static disassembly/flow/raw pcode only; no C ABI, CPU behavior, or native acceptance",
                "selected_sdk_metadata": module,
            }
            io.write_new_json(raw / "receipt.json", receipt)
            io.write_new_json(OUTPUT / f"{key}.provenance.json", receipt)
            results.append(result)
            print(key, verdict["status"], "; ".join(verdict["failures"]), flush=True)
        io.write_new_json(
            OUTPUT / "oracle.json", {"schema_version": 1, "fixtures": results}
        )
        io.write_new_json(
            OUTPUT / "provenance.json",
            {
                "schema_version": 1,
                "cohort": cohort.name,
                "manifest_sha256": MANIFEST_SHA,
                "plan_sha256": PLAN_SHA,
                "profiles": [
                    {
                        "name": row["name"],
                        "status": row["verdict"]["status"],
                        "receipt": row["name"] + ".provenance.json",
                    }
                    for row in results
                ],
                "pilot_artifacts_modified": False,
                "native_acceptance": False,
            },
        )
    finally:
        stages.close()


if __name__ == "__main__":
    run()
