# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "owned_targeted_retry", Path(__file__).with_name("run_extended_retry.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("fixed retry helper unavailable")
retry = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = retry
SPEC.loader.exec_module(retry)


class TargetedCorrectionTests(unittest.TestCase):
    def test_superh_actual_v1_delay_slot_evidence_explains_presentation_only(
        self,
    ) -> None:
        truth = retry.load(retry.v1.OUTPUT / "SuperH-v1.truth.json")
        actual = retry.load(retry.v1.OUTPUT / "SuperH-v1.oracle.json")["oracle"]
        self.assertEqual(retry.v1.validate(actual, truth)["status"], "mismatch")
        self.assertEqual(retry.validate(actual, truth)["status"], "pass")
        rows = {
            row["fixture_offset_bytes"]: row for row in actual["program_oracle"]["rows"]
        }
        for offset in (2, 8, 20):
            self.assertEqual(rows[offset]["mnemonic"], "_nop")
            self.assertTrue(rows[offset]["is_in_delay_slot"])

    def test_mnemonic_correction_requires_real_delay_slot_flag(self) -> None:
        truth = retry.load(retry.v1.OUTPUT / "SuperH-v1.truth.json")
        actual = retry.load(retry.v1.OUTPUT / "SuperH-v1.oracle.json")["oracle"]
        changed = copy.deepcopy(actual)
        row = next(
            row
            for row in changed["program_oracle"]["rows"]
            if row["fixture_offset_bytes"] == 2
        )
        row["is_in_delay_slot"] = False
        self.assertEqual(retry.validate(changed, truth)["status"], "mismatch")

    def test_non_delay_slot_wrong_opcode_is_not_normalized(self) -> None:
        truth = retry.load(retry.v1.OUTPUT / "SuperH-v1.truth.json")
        actual = retry.load(retry.v1.OUTPUT / "SuperH-v1.oracle.json")["oracle"]
        changed = copy.deepcopy(actual)
        row = next(
            row
            for row in changed["program_oracle"]["rows"]
            if row["fixture_offset_bytes"] == 10
        )
        row["mnemonic"] = "_nop"
        self.assertEqual(retry.validate(changed, truth)["status"], "mismatch")

    def test_hexagon_failure_was_actual_missing_host_helper(self) -> None:
        previous = retry.load(retry.v1.OUTPUT / "Hexagon-v1.oracle.json")
        self.assertEqual(previous["verdict"]["status"], "technical_failure")
        self.assertIn(
            "HexagonParallelInstructionHelper",
            previous["oracle"]["program_oracle"]["error"],
        )
        self.assertEqual(
            retry.io.digest(retry.io.SDK / retry.HEXAGON_JAR)["sha256"],
            retry.HEXAGON_JAR_SHA,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
