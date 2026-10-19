# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "owned_extended_producer", Path(__file__).with_name("run_extended_oracle.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("fixed extended helper unavailable")
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)


class FixedExtendedInputs(unittest.TestCase):
    def test_hardcoded_java_profiles_bind_exact_frozen_plan_bytes(self) -> None:
        plan = producer.pinned_json(producer.PLAN, producer.PLAN_SHA)
        source = producer.io.read_bounded(
            Path(__file__).with_name("ExtendedSleighOracle.java"), producer.io.MIB
        ).decode()
        entries = re.findall(
            r'new Owned\("([^"]+)", "([^"]+)", (0x[0-9a-f]+),\s*"([0-9a-f]+)"', source
        )
        self.assertEqual(len(entries), 13)
        for candidate, (key, language, base, data) in zip(plan["profiles"], entries):
            self.assertEqual(key, candidate["family"] + "-v1")
            self.assertEqual(language, candidate["language_id"])
            self.assertEqual(
                int(base, 16), int(candidate["planned_base_byte_offset"], 16)
            )
            self.assertEqual(data, candidate["bytes_hex"])

    def test_manual_function_ranges_fit_complete_owned_windows(self) -> None:
        plan = producer.pinned_json(producer.PLAN, producer.PLAN_SHA)
        for candidate in plan["profiles"]:
            family = candidate["family"]
            end = producer.MAIN_END[family]
            callee = candidate["planned_callee_offset_bytes"]
            self.assertLessEqual(end, callee)
            self.assertLess(callee, candidate["byte_length"])
            self.assertLessEqual(candidate["byte_length"], 128)
            offset = 0
            for instruction in candidate["instruction_ledger"]:
                self.assertEqual(offset, instruction["offset_bytes"])
                offset += len(bytes.fromhex(instruction["bytes_hex"]))
            self.assertEqual(offset, candidate["byte_length"])

    def test_delay_slot_and_packet_truth_boundaries_are_intrinsic(self) -> None:
        plan = producer.pinned_json(producer.PLAN, producer.PLAN_SHA)
        sh = next(row for row in plan["profiles"] if row["family"] == "SuperH")
        self.assertEqual(
            producer.MAIN_END["SuperH"], producer.RETURN_OFFSET["SuperH"] + 4
        )
        self.assertIn(
            "delay slot", sh["instruction_ledger"][-1]["owned_explanatory_asm"]
        )
        hexagon = next(row for row in plan["profiles"] if row["family"] == "Hexagon")
        for instruction in hexagon["instruction_ledger"]:
            word = int.from_bytes(bytes.fromhex(instruction["bytes_hex"]), "little")
            self.assertEqual((word >> 14) & 3, 3)

    def test_technical_unsupported_profile_is_retained_as_failure(self) -> None:
        result = producer.validate(
            {
                "program_oracle": {
                    "status": "technical_failure",
                    "error": "owned failure",
                }
            },
            {},
        )
        self.assertEqual(result["status"], "technical_failure")
        self.assertEqual(result["failures"], ["owned failure"])

    def test_changed_release_manifest_pin_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "pin differs"):
            producer.pinned_json(producer.MANIFEST, "0" * 64)

    def test_release_matches_exact_selected_pairs(self) -> None:
        plan = producer.pinned_json(producer.PLAN, producer.PLAN_SHA)
        manifest = producer.pinned_json(producer.MANIFEST, producer.MANIFEST_SHA)
        self.assertEqual(len(manifest["profiles"]), 16)
        for row in plan["profiles"]:
            selected = next(
                item for item in manifest["profiles"] if item["family"] == row["family"]
            )
            self.assertEqual(selected["language_id"], row["language_id"])
            self.assertEqual(selected["compiler_id"], "default")


if __name__ == "__main__":
    unittest.main(verbosity=2)
