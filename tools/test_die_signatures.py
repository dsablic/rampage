"""Converter tests on representative Detect It Easy scripts.

The script snippets below are trimmed from the Detect It Easy database (https://github.com/horsicq/Detect-It-Easy,
db/, commit 7eaa31a972932113aa982cc0ebfa3352a1cd07fe), Copyright (c) 2012-2026 hors and the DIE contributors,
MIT licence; see crates/rampage-detect/data/LICENSE.detect-it-easy. Some are reduced to the idiom under test.
"""

from __future__ import annotations

import unittest

from tools import die_signatures as die

# db/PE/packer_FSG.2.sg, reduced: version-only branches, detection decided after the chain.
FSG = """
// Author: horsicq <horsicq@gmail.com>
meta("packer", "FSG");

function detect() {
    if (PE.compareEP("BE........BF........BB........53BB........B280")) {
        sVersion = "1.31";
    } else if (PE.compareEP("EB02CD2003..8D..80....00..................EB02")) {
        sVersion = "1.10";
        sOptions = "Watcom C/C++ EXE";
    }

    bDetected = bDetected || Boolean(sVersion);

    return result();
}
"""

# db/PE/packer_MEW.2.sg, reduced: relative-jump patterns.
MEW = """
meta("packer", "MEW");

function detect() {
    if (PE.compareEP("e9$$$$$$$$be........8bdeadad50ad97b2")) {
        sVersion = "SE 1.1-1.2";
        bDetected = true;
    } else if (PE.compareEP("E9........000000020000000C")) {
        sVersion = "SE 1.0";
        bDetected = true;
    }

    return result();
}
"""

# db/PE/library_Intel_IPP.4.sg: a library, which says nothing about the producing tool.
IPP = """
meta("library", "Intel IPP");

function detect() {
    if (PE.isSectionNamePresent("IPPCODE") && PE.isSectionNamePresent("IPPDATA")) {
        bDetected = true;
    }

    return result();
}
"""

# db/ELF/compiler_Go.4.sg, reduced: a section disjunction, then an entry-point chain that sets the version.
GO = """
meta("compiler", "Go");

function detect() {
    if (ELF.isSectionNamePresent(".gopclntab") ||
        ELF.isSectionNamePresent(".go.buildinfo")) {
        bDetected = true;
    }

    if (ELF.compareEP("488d742408488b3c24b810174200ffe0b870f94100ffe0000000000000000000")) {
        bDetected = true;
        sVersion = "1.2.2";
    }

    return result();
}
"""


def convert(text: str, file_type: str = "PE") -> list[dict]:
    return die.convert_script(file_type, text)[1].signatures


class PatternTests(unittest.TestCase):
    def test_wildcards_text_and_offsets(self) -> None:
        self.assertEqual(die.convert_pattern("60..E8'MZ'"), "60 ?? E8 4D 5A")
        self.assertEqual(die.convert_pattern("6?", skip=2), "?? ?? 6?")
        self.assertEqual(die.convert_pattern("E9$$$$$$$$BE", jumps=True), "E9 $4 BE")
        self.assertEqual(die.convert_pattern("EB$$90", jumps=True), "EB $1 90")

    def test_inexpressible_forms_are_rejected(self) -> None:
        for pattern, kwargs in [("E9$$$$$$$$", {}), ("68########", {}), ("**4D5A", {}), ("CD+EB", {}),
                                ("6", {}), ("....", {}), ("E9$$$$$$BE", {"jumps": True})]:
            with self.subTest(pattern=pattern), self.assertRaises(die.Unsupported):
                die.convert_pattern(pattern, **kwargs)


class ScriptTests(unittest.TestCase):
    def test_version_only_chain_detected_afterwards(self) -> None:
        signatures = convert(FSG)
        self.assertEqual(
            [(s["name"], s.get("version"), s.get("options"), s["conditions"]) for s in signatures],
            [
                ("FSG", "1.31", None, [{"entry": "BE ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80"}]),
                ("FSG", "1.10", "Watcom C/C++ EXE",
                 [{"entry": "EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02"}]),
            ],
        )
        self.assertEqual(signatures[0]["kind"], "packer")

    def test_jump_patterns_convert(self) -> None:
        signatures = convert(MEW)
        self.assertEqual(signatures[0]["conditions"], [{"entry": "E9 $4 BE ?? ?? ?? ?? 8B DE AD AD 50 AD 97 B2"}])
        self.assertEqual(signatures[1]["version"], "SE 1.0")

    def test_out_of_scope_type_is_skipped(self) -> None:
        with self.assertRaisesRegex(die.Unsupported, "type out of scope"):
            convert(IPP)

    def test_disjunctions_split_and_implied_signatures_drop(self) -> None:
        signatures = convert(GO, "ELF")
        # Section-and-entry combinations add nothing over the entry alone with the same version.
        self.assertEqual(
            sorted((tuple(sorted(next(iter(c)) for c in s["conditions"])), s.get("version")) for s in signatures),
            [(("entry",), "1.2.2"), (("section",), None), (("section",), None)],
        )

    def test_negated_else_branch_needs_a_detecting_then(self) -> None:
        # The else branch fires only when the section is absent; the then branch never detects, so dropping that
        # negation would claim images DIE does not.
        script = """
        meta("protector", "X");
        function detect() {
            if (PE.isSectionNamePresent(".a")) {
                sVersion = "1";
            } else if (PE.compareEP("60E8000000005D50")) {
                bDetected = true;
            }
            return result();
        }
        """
        with self.assertRaisesRegex(die.Unsupported, "else branch"):
            convert(script)
        # With a detecting then branch, the negation is implied and the else branch converts on its own.
        exact = script.replace('sVersion = "1";', "bDetected = true;")
        self.assertEqual(len(convert(exact)), 2)

    def test_untestable_version_refinement_is_ignored(self) -> None:
        script = """
        meta("compiler", "Y");
        function detect() {
            if (PE.isSectionNamePresent(".y")) {
                bDetected = true;
                if (PE.getMajorLinkerVersion() == 6) {
                    sVersion = "6";
                }
            }
            return result();
        }
        """
        signatures = convert(script)
        self.assertEqual([(s["conditions"], s.get("version")) for s in signatures], [([{"section": ".y"}], None)])

    def test_logic_beyond_the_subset_is_skipped(self) -> None:
        cases = {
            "helper function": 'meta("packer","Z"); function f() {} function detect() { return result(); }',
            "for statement": 'meta("packer","Z"); function detect() { for (;;) {} return result(); }',
            "negated test": 'meta("packer","Z"); function detect() { if (!PE.isSectionNamePresent(".z")) '
                            '{ bDetected = true; } return result(); }',
            "condition: PE.isNet": 'meta("packer","Z"); function detect() { if (PE.isNet()) '
                                   '{ bDetected = true; } return result(); }',
        }
        for reason, script in cases.items():
            with self.subTest(reason=reason), self.assertRaisesRegex(die.Unsupported, reason):
                convert(script)

    def test_pe_bitness_and_bare_return(self) -> None:
        script = """
        meta("cryptor", "W");
        function detect() {
            if (PE.is32()) return;
            if (PE.compareEP("4883EC28E8........4883C428")) {
                bDetected = true;
            }
            return result();
        }
        """
        # `if (PE.is32()) return;` skips result(), so its else branch is never implied; nothing converts exactly.
        with self.assertRaises(die.Unsupported):
            convert(script)
        guarded = script.replace("if (PE.is32()) return;", "").replace(
            'PE.compareEP("4883EC28E8........4883C428")', '!PE.is32() && PE.compareEP("4883EC28E8........4883C428")')
        self.assertEqual(convert(guarded)[0]["conditions"],
                         [{"bits": 64}, {"entry": "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28"}])

    def test_authors_are_read_from_the_header(self) -> None:
        self.assertEqual(die.authors(FSG), "horsicq")
        self.assertEqual(die.authors("// Authors: hypn0, BJNFNE\n"), "hypn0, BJNFNE")


if __name__ == "__main__":
    unittest.main()
