#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import Any

SPEC = importlib.util.spec_from_file_location(
    "owned_extended_v1", Path(__file__).with_name("run_extended_oracle.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("fixed extended helper unavailable")
v1 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = v1
SPEC.loader.exec_module(v1)
io = v1.io
KEYS = ("SuperH", "Hexagon")
HEXAGON_JAR = "Ghidra/Processors/Hexagon/lib/Hexagon.jar"
HEXAGON_SOURCE = "Ghidra/Processors/Hexagon/lib/Hexagon-src.zip"
HEXAGON_JAR_SHA = "fb31ffa9ca8e25d86271b131bdff216a6a2aaf0d7040a32a811c34c97b4c75fd"
HEXAGON_SOURCE_SHA = "56f6c77a3dbaa0bf369705bceeeebd32e6fc2f906accc41b6750f2f55c57f68a"


def load(path: Path) -> dict[str, Any]:
    return json.loads(io.read_bounded(path, io.JSON_CAP))


def validate(actual: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    expectation = copy.deepcopy(truth)
    if truth["family"] == "SuperH":
        rows = {
            row["fixture_offset_bytes"]: row
            for row in actual.get("program_oracle", {}).get("rows", [])
        }
        for instruction in expectation["instruction_ledger"]:
            offset = instruction["offset_bytes"]
            if offset not in (2, 8, 20):
                continue
            if not rows.get(offset, {}).get("is_in_delay_slot"):
                return {
                    "status": "mismatch",
                    "failures": [f"missing intrinsic delay-slot flag at {offset}"],
                }
            instruction["owned_explanatory_asm"] = instruction[
                "owned_explanatory_asm"
            ].replace("NOP", "_NOP", 1)
    return v1.validate(actual, expectation)


def run() -> None:
    manifest = v1.pinned_json(v1.MANIFEST, v1.MANIFEST_SHA)
    old_index = load(v1.OUTPUT / "provenance.json")
    cohort = Path(tempfile.mkdtemp(prefix="targeted-v2-", dir=v1.RAW))
    with ExitStack() as stages:
        run_cohort(manifest, old_index, cohort, stages)


def run_cohort(
    manifest: dict[str, Any], old_index: dict[str, Any], cohort: Path, stages: ExitStack
) -> None:
    compile_stage = stages.enter_context(v1.owned_stage(cohort, "compile-stage"))
    classes = compile_stage / "classes"
    classes.mkdir()
    truths = []
    for family in KEYS:
        old = load(v1.OUTPUT / f"{family}-v1.truth.json")
        truth = copy.deepcopy(old)
        truth.update(
            {
                "name": family + "-v2",
                "version": 2,
                "previous_version": family + "-v1",
                "owned_encoding_changed": False,
            }
        )
        if family == "SuperH":
            truth["correction"] = {
                "kind": "SDK_delay_slot_mnemonic_presentation_not_wrong_opcode",
                "source": "SoftwareModeling-src.zip!/ghidra/app/plugin/processors/sleigh/SleighInstructionPrototype.java",
                "line": 1335,
                "fact": "getMnemonic appends an underscore prefix when this.isindelayslot is true",
                "allowed_presentations": {"2": "_nop", "8": "_nop", "20": "_nop"},
                "guard": "Only those three source-declared delay slots, and is_in_delay_slot must be true",
                "assembly_and_manual_function_extents_unchanged": True,
            }
        else:
            truth["correction"] = {
                "kind": "fixed_trusted_installed_host_module_dependency_missing_in_v1",
                "dependency": HEXAGON_JAR,
                "sha256": HEXAGON_JAR_SHA,
                "pspec_class": "ghidra.app.util.viewer.field.HexagonParallelInstructionHelper",
                "source_archive": HEXAGON_SOURCE,
                "source_archive_sha256": HEXAGON_SOURCE_SHA,
                "assembly_and_manual_function_extents_unchanged": True,
                "cpu_version": "unspecified_by_default_language_no_HVX_or_v73_authentication",
            }
        for suffix, cap in (("bin", 128), ("asm", io.MIB)):
            data = io.read_bounded(v1.OUTPUT / f"{family}-v1.{suffix}", cap)
            with (v1.OUTPUT / f"{family}-v2.{suffix}").open("xb") as output:
                output.write(data)
        io.write_new_json(v1.OUTPUT / f"{family}-v2.truth.json", truth)
        truths.append(truth)
    classpath = os.pathsep.join(str(io.SDK / "Ghidra" / name) for name in io.CLASSPATH)
    source_names = (
        "SleighOracle.java",
        "run_oracle.py",
        "ExtendedSleighOracle.java",
        "run_extended_oracle.py",
        "ExtendedSleighOracleRetry.java",
        "run_extended_retry.py",
        "test_run_extended_retry.py",
        "test_stage_cleanup.py",
    )
    common = {
        "source/" + name: io.ROOT / "tools/sleigh-fixture" / name
        for name in source_names
    }
    common.update(
        {
            "sdk/Ghidra/" + name: io.SDK / "Ghidra" / name
            for name in io.CLASSPATH + list(io.API_SOURCES)
        }
    )
    common.update(
        {"sdk/" + name: io.SDK / name for name in (HEXAGON_JAR, HEXAGON_SOURCE)}
    )
    common["inputs/admission.json"] = v1.MANIFEST
    for truth in truths:
        for suffix in ("bin", "asm", "truth.json"):
            common["fixtures/" + truth["name"] + "." + suffix] = v1.OUTPUT / (
                truth["name"] + "." + suffix
            )
    launchers = {
        name: (io.JDK / name).resolve(strict=True) for name in ("java", "javac")
    }
    common.update({"jdk/bin/" + name: path for name, path in launchers.items()})
    before_compile = v1.snapshot(common, io.Budget())
    if before_compile["sdk/" + HEXAGON_JAR]["sha256"] != HEXAGON_JAR_SHA:
        raise ValueError("fixed Hexagon host dependency differs")
    if before_compile["sdk/" + HEXAGON_SOURCE]["sha256"] != HEXAGON_SOURCE_SHA:
        raise ValueError("fixed Hexagon source archive differs")
    io.write_new_json(cohort / "compile-before.json", before_compile)
    saved_sources = cohort / "source-tool-snapshot"
    saved_sources.mkdir()
    for name in source_names:
        data = io.read_bounded(common["source/" + name], io.MIB)
        if v1.sha(data) != before_compile["source/" + name]["sha256"]:
            raise ValueError("retry source changed before preservation")
        with (saved_sources / name).open("xb") as output:
            output.write(data)
    command = [str(launchers["javac"]), "-cp", classpath, "-d", str(classes)]
    command.extend(
        str(common["source/" + name])
        for name in (
            "SleighOracle.java",
            "ExtendedSleighOracle.java",
            "ExtendedSleighOracleRetry.java",
        )
    )
    compilation = v1.command_run(command, classes.parent, cohort, "compile")
    io.write_new_json(cohort / "compile-command.json", compilation)
    if compilation.get("exit_code") != 0:
        raise RuntimeError(
            "targeted helper compilation failed; original compile logs retained"
        )
    if before_compile != v1.snapshot(common, io.Budget()):
        raise ValueError("retry compile inputs changed")
    compiled = io.class_inventory(classes)
    io.write_new_json(cohort / "classes-after-compile.json", compiled)
    latest = []
    try:
        for truth in truths:
            family, key = truth["family"], truth["name"]
            raw = Path(tempfile.mkdtemp(prefix=key + "-attempt-", dir=cohort))
            profile_stages = stages.enter_context(ExitStack())
            stage = profile_stages.enter_context(v1.owned_stage(raw, "stage"))
            files = dict(common)
            selected = next(
                row for row in manifest["profiles"] if row["family"] == family
            )
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
            before = v1.snapshot(files, budget)
            for field in ("sla_path", "pspec_path", "cspec_path", "ldefs_path"):
                admitted = next(
                    item
                    for item in manifest["files"]
                    if item["path"] == selected[field]
                )
                if before["sdk/" + selected[field]]["sha256"] != admitted["sha256"]:
                    raise ValueError("retry SDK resource differs from released bytes")
            if io.class_inventory(classes) != compiled:
                raise ValueError("retry classes changed before launch")
            io.write_new_json(raw / "before.json", before)
            runtime_cp = os.pathsep.join((str(classes), classpath))
            if family == "Hexagon":
                runtime_cp += os.pathsep + str(io.SDK / HEXAGON_JAR)
            cmd = [
                str(launchers["java"]),
                "-Xmx512m",
                "-Djava.awt.headless=true",
                f"-Duser.home={stage / 'home'}",
                f"-Djava.io.tmpdir={stage / 'tmp'}",
                "-cp",
                runtime_cp,
                "ExtendedSleighOracleRetry",
                key,
                str(v1.OUTPUT),
                str(raw / "oracle.json"),
            ]
            receipt_command: dict[str, Any] = {
                "argv": cmd,
                "compiled_classes_before_launch": compiled,
            }
            io.write_new_json(raw / "command-before-launch.json", receipt_command)
            receipt_command.update(v1.command_run(cmd, stage, raw, "oracle"))
            after_classes = io.class_inventory(classes)
            receipt_command["compiled_classes_after_execution"] = after_classes
            receipt_command["compiled_classes_unchanged"] = compiled == after_classes
            after_budget = io.Budget()
            after = v1.snapshot(files, after_budget)
            io.write_new_json(raw / "after.json", after)
            io.write_new_json(raw / "command.json", receipt_command)
            if receipt_command.get("exit_code") == 0:
                actual = load(raw / "oracle.json")
            else:
                actual = {
                    "fixture": key,
                    "program_oracle": {
                        "status": "technical_failure",
                        "error": "Java failed; logs retained",
                    },
                }
            verdict = validate(actual, truth)
            if before != after or compiled != after_classes:
                verdict = {
                    "status": "technical_failure",
                    "failures": ["retry input/class binding changed"],
                }
            result = {
                "name": key,
                "family": family,
                "language_id": truth["language_id"],
                "verdict": verdict,
                "oracle": actual,
            }
            io.write_new_json(v1.OUTPUT / f"{key}.oracle.json", result)
            profile_stages.close()
            old_receipt = load(v1.OUTPUT / f"{family}-v1.provenance.json")
            receipt = {
                "schema_version": 1,
                "kind": "targeted_v2_static_oracle",
                "attempt": raw.name,
                "fixture": key,
                "verdict": verdict,
                "previous_attempt": old_receipt["attempt"],
                "correction": truth["correction"],
                "inputs_before": before,
                "inputs_after": after,
                "unchanged": before == after,
                "command": json.loads(io.sanitize(json.dumps(receipt_command), stage)),
                "limits": {
                    **old_receipt["limits"],
                    "before_reserved_bytes": budget.used_bytes,
                    "before_actual_read_bytes": budget.read_bytes,
                    "after_actual_read_bytes": after_budget.read_bytes,
                },
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
                "stage_removed": True,
                "target_execution": False,
                "network": False,
                "claim_limit": "Actual SDK static facts, not CPU semantics, C ABI, native acceptance or retroattestation",
            }
            io.write_new_json(raw / "receipt.json", receipt)
            io.write_new_json(v1.OUTPUT / f"{key}.provenance.json", receipt)
            latest.append(result)
            print(key, verdict["status"], "; ".join(verdict["failures"]), flush=True)
        current = []
        current_truth = []
        for family in v1.NAMES:
            version = "v2" if family in KEYS else "v1"
            current.append(load(v1.OUTPUT / f"{family}-{version}.oracle.json"))
            current_truth.append(load(v1.OUTPUT / f"{family}-{version}.truth.json"))
        io.write_new_json(
            v1.OUTPUT / "oracle-current.json",
            {"schema_version": 1, "fixtures": current},
        )
        io.write_new_json(
            v1.OUTPUT / "truth-current.json",
            {"schema_version": 1, "fixtures": current_truth},
        )
        io.write_new_json(
            v1.OUTPUT / "provenance-current.json",
            {
                "schema_version": 1,
                "initial_cohort": old_index["cohort"],
                "targeted_retry_cohort": cohort.name,
                "initial_records_unchanged": True,
                "manifest_sha256": v1.MANIFEST_SHA,
                "profiles": [
                    {
                        "name": row["name"],
                        "status": row["verdict"]["status"],
                        "receipt": str(row["name"]) + ".provenance.json",
                    }
                    for row in current
                ],
                "target_execution": False,
                "native_acceptance": False,
            },
        )
    finally:
        stages.close()


if __name__ == "__main__":
    run()
