"""Source-only lane regression tests; live Ghidra/native validation is a separate parent gate."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import select
import shlex
import signal
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tools import cpp_virtual_corpus as corpus

FIXTURES = corpus.ROOT / "tests/fixtures/debug-cpp-virtuals"


def temporary_parent() -> Path:
    return Path(os.environ.get("TMPDIR") or str(corpus.DEFAULT_TEMP))


def independent_methods() -> tuple[dict[str, Any], list[corpus.Method]]:
    oracle = json.loads((FIXTURES / "oracle.json").read_text())
    source = (FIXTURES / oracle["groups"]["records"]["source"]).read_text()
    methods = corpus.load_methods(oracle, source)
    for index, method in enumerate(methods):
        method.address = 0x401000 + index * 16
        method.size = 8
    return oracle, methods


def independent_receipt(
    oracle: dict[str, Any], methods: list[corpus.Method]
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    emitted_names: dict[str, str] = {}
    for index, record_key in enumerate(oracle["groups"]["records"]["records"]):
        record = oracle["records"][record_key]
        expected = oracle["layouts"][record["layout"]]
        name = "consumer_" + record_key
        emitted_names[record["tag"]] = name
        layout = {
            "name": name,
            "size": expected["size"],
            "alignment": expected["alignment"],
            "organization": {
                "pointer_size": 8,
                "int_size": 4,
                "long_size": 8,
                "scalar_alignments": [1, 2, 4, 8],
            },
        }
        rows.append(
            {
                "kind": "type",
                "source": "checked",
                "status": "verified",
                "data": {
                    "original_name": record["tag"],
                    "unit_offset": 0,
                    "die_offset": 16 + index * 16,
                    "layout": layout,
                },
            }
        )
        fields = [
            {
                "name": "rampage_vptr",
                "offset": 0,
                "size": 8,
                "ty": {
                    "kind": "pointer",
                    "name": "",
                    "size": 8,
                    "alignment": 8,
                    "pointee": {
                        "name": "void",
                        "kind": "void",
                        "size": 0,
                        "alignment": 1,
                    },
                },
            }
        ]
        for fact in expected["fields"]:
            signed = fact["name"] == "count"
            fields.append(
                {
                    "name": fact["name"],
                    "offset": fact["offset"],
                    "size": fact["size"],
                    "ty": {
                        "kind": "scalar",
                        "scalar": {
                            "name": "int4" if signed else "uint1",
                            "kind": "signed_integer" if signed else "unsigned_integer",
                            "size": fact["size"],
                            "alignment": fact["alignment"],
                        },
                    },
                }
            )
        rows.extend(
            {
                "kind": "field",
                "source": "checked",
                "status": "verified",
                "type_name": name,
                "data": member,
            }
            for member in fields
        )
        rows[-len(fields)]["storage_role"] = (
            "opaque_projection_storage_not_exact_producer_type"
        )
    for index, method in enumerate(methods):
        result = (
            "void" if method.write else "uint4" if method.field == "tail" else "int4"
        )
        arguments = emitted_names[method.record] + " * self"
        if method.write:
            arguments += ", int4 replacement"
        rows.append(
            {
                "kind": "function",
                "source": "checked",
                "status": "approved",
                "data": {
                    "original_name": method.symbol,
                    "address": hex(method.address),
                    "unit_offset": 0,
                    "die_offset": 64 + index * 16,
                    "declaration": f"{result} method_{index}({arguments});",
                    "dependencies": [emitted_names[method.record]],
                },
            }
        )
    for index, record_key in enumerate(oracle["groups"]["records"]["records"]):
        record = oracle["records"][record_key]
        fact = oracle["layouts"][record["layout"]]
        role_base = 512 + index * 64
        rows.append(
            {
                "kind": "projection",
                "source": "virtual_evidence",
                "status": "read_only",
                "type_name": emitted_names[record["tag"]],
                "storage_role": "opaque_projection_storage_not_exact_producer_type",
                "data": {
                    "kind": "opaque_vptr",
                    "field_index": 0,
                    "record_id": {"unit_offset": 0, "die_offset": 16 + index * 16},
                    "member_id": {"unit_offset": 0, "die_offset": role_base},
                    "pointer_id": {"unit_offset": 0, "die_offset": role_base + 1},
                    "pointee_pointer_id": {
                        "unit_offset": 0,
                        "die_offset": role_base + 2,
                    },
                    "subroutine_id": {"unit_offset": 0, "die_offset": role_base + 3},
                    "source": {
                        "unit_offset": 0,
                        "language": 0x21,
                        "dwarf_version": 5,
                        "address_size": 8,
                    },
                    "record_byte_size": fact["size"],
                    "record_alignment": fact["alignment"],
                    "member_offset": 0,
                    "member_byte_size": None,
                    "member_alignment": None,
                    "pointer_byte_size": 8,
                    "pointer_alignment": None,
                    "pointee_pointer_byte_size": 8,
                    "pointee_pointer_alignment": None,
                },
            }
        )
    return {
        "ok": True,
        "status": "preview",
        "review_sha256": "a" * 64,
        "image_sha256": "b" * 64,
        "compiler_spec_sha256": "c" * 64,
        "details": rows,
        "offset": 0,
        "limit": 1000,
        "next_offset": None,
        "details_total": len(rows),
    }


def accepted_inputs() -> tuple[
    dict[str, Any], list[corpus.Method], dict[str, Any], list[dict[str, Any]]
]:
    oracle, methods = independent_methods()
    receipt = independent_receipt(oracle, methods)
    layouts = corpus.validate_consumer(receipt, oracle, methods, "b" * 64)
    return oracle, methods, receipt, layouts


def native_response(method: corpus.Method, code: str | None = None) -> dict[str, Any]:
    return_name = (
        "void" if method.write else "uint4" if method.field == "tail" else "int4"
    )
    if code is None:
        base = "replacement" if method.write else "self->" + method.field
        delta = method.expected.delta
        if delta:
            base += " + " + hex(delta)
        body = (
            "self->count = " + base + "; return;"
            if method.write
            else "return " + base + ";"
        )
        code = "void example() { " + body + " }"
    parameters: list[dict[str, Any]] = [
        {
            "name": "self",
            "data_type": {"name": method.layout_name + " *", "size": 8},
            "storage": {
                "kind": "processor",
                "space": "register",
                "address": 56,
                "size": 8,
                "pieces": [],
            },
        }
    ]
    if method.write:
        parameters.append(
            {
                "name": "replacement",
                "data_type": {"name": "int4", "size": 4},
                "storage": {
                    "kind": "processor",
                    "space": "register",
                    "address": 48,
                    "size": 4,
                    "pieces": [],
                },
            }
        )
    return {
        "version": 4,
        "status": "ok",
        "output": {
            "language_id": "x86:LE:64:default:gcc",
            "data_organization": {"pointer": 8, "int": 4, "long": 8},
            "text": code,
            "tokens": [],
            "structure": {
                "provenance": "engine_recovered",
                "signature": {
                    "return_type": {"name": return_name, "size": method.return_size},
                    "calling_convention": "__stdcall",
                    "variadic": False,
                    "parameters": parameters,
                },
                "diagnostics": {
                    "bad_data": False,
                    "unimplemented": False,
                    "unresolved_calls": 0,
                    "unresolved_indirect_jumps": 0,
                    "partial_jump_tables": 0,
                    "warnings": [],
                },
                "variables": [],
                "blocks": [],
                "calls": [],
                "jump_tables": [],
            },
        },
    }


def reference_row(method: corpus.Method) -> dict[str, Any]:
    oracle = json.loads((FIXTURES / "oracle.json").read_text())
    fact = next(
        item
        for item in oracle["groups"]["records"]["methods"]
        if item["symbol"] == method.symbol
    )
    expression_fact = fact["expression"]
    write = fact["access"] == "write"
    base = (
        "replacement_ref"
        if expression_fact["source"] == "parameter"
        else "object_ref->" + expression_fact["name"]
    )
    addition = expression_fact["add"]
    if addition:
        base += " + " + str(addition)
    body = (
        "object_ref->count = " + base + "; return;" if write else "return " + base + ";"
    )
    parameters: list[dict[str, Any]] = [
        {
            "name": "object_ref",
            "size": 8,
            "kind": "record_pointer",
            "record_name": "consumer_" + fact["record"],
            "storage": {
                "kind": "processor",
                "space": "register",
                "address": 56,
                "size": 8,
            },
        }
    ]
    if write:
        parameters.append(
            {
                "name": "replacement_ref",
                "size": 4,
                "kind": "signed_integer",
                "storage": {
                    "kind": "processor",
                    "space": "register",
                    "address": 48,
                    "size": 4,
                },
            }
        )
    return {
        "symbol": method.symbol,
        "address": method.address,
        "ok": True,
        "text": "void independently_rendered() { " + body + " }",
        "return_size": fact["return_size"],
        "calling_convention": "__stdcall",
        "parameters": parameters,
        "return_kind": "void"
        if write
        else "unsigned_integer"
        if fact["field"] == "tail"
        else "signed_integer",
        "warning": "",
        "decompile_inner_seconds": 0.01,
    }


def reference_export(
    request: dict[str, Any], methods: list[corpus.Method]
) -> dict[str, Any]:
    root = Path(request.get("scratch_root", str(FIXTURES))).resolve()
    return {
        "schema": "rampage-cpp-virtual-reference-v1",
        "ok": True,
        "input_sha256": request["input_sha256"],
        "memory_sha256": request["memory_sha256"],
        "memory_validated": True,
        "layout_validated": True,
        "language_id": "x86:LE:64:default",
        "compiler_id": "gcc",
        "default_model": "__stdcall",
        "effective_options": copy.deepcopy(corpus.OPTIONS),
        "specifications": request["specifications"],
        "ghidra_version": "12.1.4",
        "analysis_mode": "DISABLED",
        "scratch_settings_owned": True,
        "runtime_directories": {
            "user_home": str(root / "h"),
            "java_temp": str(root),
            "application_settings": str(root / "gs/ghidra/version"),
            "application_cache": str(root / "gc/ghidra"),
            "application_temp": str(root / "gt/ghidra"),
        },
        "methods": [reference_row(method) for method in methods],
    }


def captured(
    value: dict[str, Any], command: list[str] | None = None
) -> corpus.ProcessResult:
    return corpus.ProcessResult(
        command or ["fake"], 0, json.dumps(value).encode(), b"", 0.01, None, 1024, 1
    )


def fake_parse_types_error(request: dict[str, Any]) -> dict[str, Any] | None:
    for index, operation in enumerate(request["operations"]):
        if operation["op"] != "parse_types":
            continue
        declaration = operation.get("declarations")
        if not isinstance(declaration, str) or not re.fullmatch(
            r"\s*struct\s+[A-Za-z_][A-Za-z_0-9]*\s*\{[^{}]*\}\s*;\s*", declaration
        ):
            return {
                "version": 4,
                "status": "error",
                "message": f"operation {index}: fake native parser requires one top-level record declaration",
            }
    return None


def tiny_elf() -> bytes:
    data = bytearray(640)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        2,
        62,
        1,
        0x400258,
        64,
        192,
        0,
        64,
        56,
        1,
        64,
        4,
        2,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, 640, 656, 1)
    struct.pack_into("<IIQQQQIIQQ", data, 256, 0, 1, 6, 0x400258, 600, 8, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 320, 0, 3, 0, 0, 448, 6, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 384, 0, 2, 0, 0, 464, 48, 2, 0, 8, 24)
    data[448:454] = b"\0tiny\0"
    struct.pack_into("<IBBHQQ", data, 488, 1, 0x12, 0, 1, 0x400258, 8)
    data[600:608] = b"\x90" * 8
    return bytes(data)


class ExpressionTests(unittest.TestCase):
    def test_actual_parameter_identity_is_not_substring_matching(self) -> None:
        with self.assertRaises(corpus.CorpusError):
            corpus.rendered_expression(
                "int f() { return notself->count; }", ["self"], False
            )
        actual = corpus.rendered_expression(
            "int f() { return object_7->count; }", ["object_7"], False
        )
        self.assertEqual(actual, corpus.Expression("field:count"))

    def test_promotions_and_hexadecimal_peer_arithmetic(self) -> None:
        self.assertEqual(
            corpus.expression("(uint)((unsigned char)self->tail) + 1"),
            corpus.Expression("field:tail", 1),
        )
        self.assertEqual(
            corpus.expression("replacement + 0xfffffffd"),
            corpus.Expression("parameter:replacement", 0xFFFFFFFD),
        )

    def test_independent_peer_oracle_is_checked_against_source(self) -> None:
        oracle = json.loads((FIXTURES / "oracle.json").read_text())
        source = (FIXTURES / "records.cpp").read_text()
        bodies = {
            "readCount": "return count + 17;",
            "writeCount": "count = replacement - 3;",
            "readTail": "return tail + 1;",
        }
        for name, body in bodies.items():
            source = re.sub(
                r"(PeerRecord::" + name + r"\s*\([^()]*\)\s*)\{[^{}]*\}",
                lambda match, body=body: match.group(1) + "{ " + body + " }",
                source,
            )
        methods = corpus.load_methods(oracle, source)
        peer = [method for method in methods if method.record == "PeerRecord"]
        self.assertEqual(
            [method.expected.delta for method in peer], [17, 0xFFFFFFFD, 1]
        )
        changed = copy.deepcopy(oracle)
        changed["groups"]["records"]["methods"][3]["expression"]["add"] = 18
        with self.assertRaisesRegex(
            corpus.CorpusError, "source and independent oracle disagree"
        ):
            corpus.load_methods(changed, source)

    def test_static_cast_tail_promotion_matches_independent_oracle(self) -> None:
        oracle = json.loads((FIXTURES / "oracle.json").read_text())
        source = (FIXTURES / "records.cpp").read_text()
        methods = corpus.load_methods(oracle, source)
        tail = next(
            method
            for method in methods
            if method.record == "PeerRecord" and method.field == "tail"
        )
        self.assertEqual(tail.expected, corpus.Expression("field:tail", 1))

    def test_rejects_narrowing_and_signed_tail_casts(self) -> None:
        for text in (
            "(byte)self->count",
            "(char)self->tail",
            "(uint1)(self->tail + 1)",
            "(int8)self->count",
            "(short)replacement",
        ):
            with self.subTest(text=text), self.assertRaises(corpus.CorpusError):
                corpus.expression(text)

    def test_rejects_unsupported_grammar_and_side_effects(self) -> None:
        bodies = [
            "return self->count; callback();",
            "self->count++; return self->count;",
            "return other->count;",
            "return self->count + self->count;",
            "return 17;",
            "return self[0].count;",
            "if (self) { return self->count; }",
            "return *self;",
            "return self->count ? 1 : 2;",
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(corpus.CorpusError):
                corpus.rendered_expression("int f() {" + body + "}", ["self"], False)

    def test_store_requires_actual_lvalue_and_replacement(self) -> None:
        actual = corpus.rendered_expression(
            "void f() { object->count = next - 3; return; }", ["object", "next"], True
        )
        self.assertEqual(actual, corpus.Expression("parameter:replacement", 0xFFFFFFFD))
        for body in (
            "self->count + 0 = replacement;",
            "self->tail = replacement;",
            "self->count == replacement;",
            "self->count = callback();",
            "self->count = replacement; other();",
        ):
            with self.subTest(body=body), self.assertRaises(corpus.CorpusError):
                corpus.rendered_expression(
                    "void f() {" + body + "}", ["self", "replacement"], True
                )


class SchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle, self.methods, self.receipt, self.layouts = accepted_inputs()

    def test_json_duplicate_keys_and_nonfinite_values_are_refused(self) -> None:
        for data in (
            b'{"ok":true,"ok":false}',
            b'{"value":NaN}',
            b'{"value":1e9999}',
            b"[]",
            b"{broken",
        ):
            with self.subTest(data=data), self.assertRaises(corpus.CorpusError):
                corpus.decode_json(data, "fake result")

    def test_opaque_vptr_integer_callback_and_undefined_lookalikes_fail(self) -> None:
        for wrong in (
            {
                "kind": "scalar",
                "scalar": {
                    "kind": "unsigned_integer",
                    "name": "uint8",
                    "size": 8,
                    "alignment": 8,
                },
            },
            {
                "kind": "pointer",
                "name": "callback",
                "size": 8,
                "alignment": 8,
                "pointee": {"name": "void", "kind": "void", "size": 0, "alignment": 1},
            },
            {"kind": "undefined", "size": 8},
        ):
            receipt = copy.deepcopy(self.receipt)
            receipt["details"][1]["data"]["ty"] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(corpus.CorpusError):
                corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64)

    def test_missing_projection_and_pointer_alignment_fail(self) -> None:
        for kind in ("projection", "alignment"):
            receipt = copy.deepcopy(self.receipt)
            if kind == "projection":
                receipt["details"] = [
                    row for row in receipt["details"] if row.get("kind") != "projection"
                ]
            else:
                receipt["details"][1]["data"]["ty"]["alignment"] = 4
            with self.subTest(kind=kind), self.assertRaises(corpus.CorpusError):
                corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64)

    def test_exact_mangled_method_and_elf_address_are_required(self) -> None:
        for kind in ("name", "address", "dependency"):
            receipt = copy.deepcopy(self.receipt)
            row = next(row for row in receipt["details"] if row["kind"] == "function")
            if kind == "name":
                row["data"]["original_name"] = "readCount"
            elif kind == "address":
                row["data"]["address"] = hex(self.methods[0].address + 1)
            else:
                row["data"]["dependencies"] = [self.methods[-1].layout_name]
            with self.subTest(kind=kind), self.assertRaises(corpus.CorpusError):
                corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64)

    def test_consumer_record_identity_cannot_merge(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        records = [row for row in receipt["details"] if row["kind"] == "type"]
        records[1]["data"]["die_offset"] = records[0]["data"]["die_offset"]
        with self.assertRaises(corpus.CorpusError):
            corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64)

    def test_const_this_implicit_this_and_bad_return_width_fail(self) -> None:
        for declaration in (
            "int4 method_0(const consumer_checked * self);",
            "int4 method_0(consumer_checked * this);",
            "int8 method_0(consumer_checked * self);",
            "int4 method_0(consumer_checked self);",
            "int4 method_0(void * self);",
        ):
            receipt = copy.deepcopy(self.receipt)
            row = next(row for row in receipt["details"] if row["kind"] == "function")
            row["data"]["declaration"] = declaration
            with (
                self.subTest(declaration=declaration),
                self.assertRaises(corpus.CorpusError),
            ):
                corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64)

    def test_unknown_rows_do_not_supply_inputs_but_remain_coverage(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["details"].extend(
            [
                {
                    "kind": "virtual_proof",
                    "source": "checked",
                    "status": "unverified",
                    "data": {"slot": 0},
                },
                {
                    "kind": "warning",
                    "source": "checked",
                    "text": "unsupported negative control",
                },
            ]
        )
        actual = corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64)
        self.assertEqual(actual, self.layouts)
        warnings = corpus.collect_warnings(receipt)
        self.assertEqual(len(warnings), 4)

    def test_final_projection_rows_bind_checked_type_and_storage_roles(self) -> None:
        self.assertTrue(
            all(
                "projections" not in row["data"]
                for row in self.receipt["details"]
                if row["kind"] == "type"
            )
        )
        self.assertEqual(
            corpus.validate_consumer(
                self.receipt, self.oracle, self.methods, "b" * 64, 5
            ),
            self.layouts,
        )
        for mutation in (
            "duplicate",
            "source",
            "record",
            "role_cu",
            "role_alias",
            "language",
            "version",
            "marker",
        ):
            receipt = copy.deepcopy(self.receipt)
            row = next(
                item for item in receipt["details"] if item["kind"] == "projection"
            )
            if mutation == "duplicate":
                receipt["details"].append(copy.deepcopy(row))
            elif mutation == "source":
                row["source"] = "producer"
            elif mutation == "record":
                row["data"]["record_id"]["die_offset"] += 16
            elif mutation == "role_cu":
                row["data"]["pointer_id"]["unit_offset"] = 8
            elif mutation == "role_alias":
                row["data"]["pointer_id"] = copy.deepcopy(row["data"]["member_id"])
            elif mutation == "language":
                row["data"]["source"]["language"] = 0x0C
            elif mutation == "version":
                row["data"]["source"]["dwarf_version"] = 4
            else:
                receipt["details"][1].pop("storage_role")
            with self.subTest(mutation=mutation), self.assertRaises(corpus.CorpusError):
                corpus.validate_consumer(
                    receipt, self.oracle, self.methods, "b" * 64, 5
                )

    def test_projection_join_ignores_producer_fields_but_not_missing_evidence(
        self,
    ) -> None:
        receipt = copy.deepcopy(self.receipt)
        producer = copy.deepcopy(receipt["details"][1])
        producer["source"] = "producer"
        producer["status"] = "preview_only"
        producer["data"]["ty"] = {"kind": "undefined", "size": 8}
        receipt["details"].insert(0, producer)
        self.assertEqual(
            corpus.validate_consumer(receipt, self.oracle, self.methods, "b" * 64),
            self.layouts,
        )

    def test_worker_protocol_carries_exact_memory_and_context(self) -> None:
        image = corpus.parse_elf(tiny_elf())
        request = corpus.worker_request(
            image, self.layouts, self.methods, self.methods[0], "c" * 64
        )
        self.assertEqual(request["mappings"], image.mappings)
        assertions = [
            row
            for row in request["operations"]
            if row["op"] == "assert_plain_struct_layout"
        ]
        self.assertEqual([row["layout"] for row in assertions], self.layouts)
        self.assertTrue(all(row["expected_context"] == "c" * 64 for row in assertions))
        prototypes = [
            row["declaration"]
            for row in request["operations"]
            if row["op"] == "prototype"
        ]
        self.assertEqual(prototypes, [method.declaration for method in self.methods])

    def test_worker_parses_each_record_before_all_assertions_and_prototypes(
        self,
    ) -> None:
        image = corpus.parse_elf(tiny_elf())
        request = corpus.worker_request(
            image, self.layouts, self.methods, self.methods[0], "c" * 64
        )
        operations = request["operations"]
        count = len(self.layouts)
        self.assertEqual(count, 2)
        self.assertEqual(
            [item["op"] for item in operations],
            ["parse_types"] * count
            + ["assert_plain_struct_layout"] * count
            + ["symbol", "prototype"] * len(self.methods),
        )
        self.assertEqual(len(operations), 2 * count + 2 * len(self.methods))
        names = []
        for operation, layout in zip(operations[:count], self.layouts):
            definitions = re.findall(
                r"\bstruct\s+([A-Za-z_][A-Za-z_0-9]*)\s*\{", operation["declarations"]
            )
            self.assertEqual(definitions, [layout["name"]])
            self.assertEqual(operation["declarations"].count("{"), 1)
            self.assertEqual(operation["declarations"].count("}"), 1)
            names.extend(definitions)
        self.assertEqual(len(set(names)), count)
        self.assertIsNone(fake_parse_types_error(request))
        bad = copy.deepcopy(request)
        bad["operations"] = [
            {
                "op": "parse_types",
                "declarations": "\n".join(
                    operation["declarations"] for operation in operations[:count]
                ),
            }
        ] + operations[count:]
        error = fake_parse_types_error(bad)
        self.assertIsNotNone(error)
        self.assertEqual(error["status"] if error else None, "error")
        with self.assertRaisesRegex(corpus.CorpusError, "operation 0:.*one top-level"):
            corpus.native_output(error if error else {}, self.methods[0])


class PaginationTests(unittest.TestCase):
    def setUp(self) -> None:
        oracle, methods = independent_methods()
        self.receipt = independent_receipt(oracle, methods)

    def test_page_hash_drift_fails_closed(self) -> None:
        first = copy.deepcopy(self.receipt)
        first["details"] = first["details"][:1]
        first["next_offset"] = 1
        second = copy.deepcopy(self.receipt)
        second["offset"] = 1
        second["review_sha256"] = "f" * 64
        with (
            mock.patch.object(
                corpus, "run_process", side_effect=[captured(first), captured(second)]
            ),
            self.assertRaisesRegex(corpus.CorpusError, "changed review_sha256"),
        ):
            corpus.collect_review(Path("cli"), Path("copy"), Path("scratch"), 1, {})

    def test_ten_page_bound_does_not_silently_skip_evidence(self) -> None:
        pages = []
        for index in range(10):
            receipt = {
                **self.receipt,
                "details": [self.receipt["details"][0]],
                "offset": index,
                "next_offset": index + 1,
                "details_total": 11,
            }
            pages.append(captured(receipt))
        with (
            mock.patch.object(corpus, "run_process", side_effect=pages),
            self.assertRaisesRegex(corpus.CorpusError, "ten pages"),
        ):
            corpus.collect_review(Path("cli"), Path("copy"), Path("scratch"), 1, {})

    def test_missing_last_page_rows_are_not_accepted(self) -> None:
        receipt = {**self.receipt, "details": self.receipt["details"][:1]}
        with (
            mock.patch.object(corpus, "run_process", return_value=captured(receipt)),
            self.assertRaisesRegex(corpus.CorpusError, "missing evidence"),
        ):
            corpus.collect_review(Path("cli"), Path("copy"), Path("scratch"), 1, {})

    def test_separate_projection_rows_can_arrive_on_later_pages(self) -> None:
        oracle, methods = independent_methods()
        split = next(
            index
            for index, row in enumerate(self.receipt["details"])
            if row["kind"] == "projection"
        )
        first = {
            **self.receipt,
            "details": self.receipt["details"][:split],
            "next_offset": split,
        }
        second = {
            **self.receipt,
            "details": self.receipt["details"][split:],
            "offset": split,
        }
        with mock.patch.object(
            corpus, "run_process", side_effect=[captured(first), captured(second)]
        ):
            receipt, _processes = corpus.collect_review(
                Path("cli"), Path("copy"), Path("scratch"), 1, {}
            )
        self.assertEqual(
            len(corpus.validate_consumer(receipt, oracle, methods, "b" * 64)), 2
        )


class ResultTests(unittest.TestCase):
    def setUp(self) -> None:
        _oracle, self.methods, _receipt, _layouts = accepted_inputs()
        self.method = self.methods[0]

    def test_native_partial_recovery_is_retained_as_a_failure(self) -> None:
        response = native_response(self.method)
        response["output"]["structure"]["diagnostics"]["bad_data"] = True
        with self.assertRaisesRegex(corpus.CorpusError, "partial recovery"):
            corpus.native_output(response, self.method)

    def test_missing_result_and_wrong_protocol_fail(self) -> None:
        responses = [
            {"status": "ok", "version": 4},
            {"status": "error", "version": 4, "message": "refused"},
            {**native_response(self.method), "version": 3},
        ]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(corpus.CorpusError):
                corpus.native_output(response, self.method)

    def test_native_protocol_failure_preserves_worker_syntax_diagnostic(self) -> None:
        message = (
            "operation 0: decompiler: Syntax error at line 5 in stream\nstruct \n^--\n"
        )
        with self.assertRaises(corpus.CorpusError) as failure:
            corpus.native_output(
                {"version": 4, "status": "error", "message": message}, self.method
            )
        self.assertIn(message, str(failure.exception))

    def test_native_undefined_return_is_not_a_typed_integer(self) -> None:
        response = native_response(self.method)
        response["output"]["structure"]["signature"]["return_type"]["name"] = (
            "undefined4"
        )
        with self.assertRaises(corpus.CorpusError):
            corpus.native_output(response, self.method)

    def test_fresh_cli_uses_actual_parameters_and_requires_typed_record(self) -> None:
        output = native_response(self.method)["output"]
        result = {
            "address": hex(self.method.address),
            "language_id": output["language_id"],
            "code": output["text"].replace("self", "object_5"),
            "structure": output["structure"],
            "recovery_status": "no_reported_issues",
        }
        parameter = result["structure"]["signature"]["parameters"][0]
        parameter["name"] = "object_5"
        self.assertEqual(
            corpus.integration_expression(result, self.method), self.method.expected
        )
        parameter["data_type"]["name"] = "void *"
        with self.assertRaisesRegex(corpus.CorpusError, "self record mismatch"):
            corpus.integration_expression(result, self.method)

    def test_parameter_storage_must_be_observed_and_match(self) -> None:
        native = corpus.native_output(native_response(self.method), self.method)
        row = reference_row(self.method)
        row["parameters"][0]["storage"]["address"] += 8
        with self.assertRaisesRegex(corpus.CorpusError, "storage mismatch"):
            corpus.match_parameter_storage(row, self.method, native)
        with self.assertRaisesRegex(corpus.CorpusError, "unavailable"):
            corpus.match_parameter_storage(
                reference_row(self.method), self.method, None
            )
        self.assertEqual(
            corpus.validate_reference_method(row, self.method), self.method.expected
        )
        case: dict[str, Any] = {"failures": []}
        corpus.score_reference_case(case, reference_row(self.method), self.method, None)
        self.assertTrue(case["reference_success"])
        self.assertTrue(case["reference_oracle_match"])
        self.assertFalse(case["settings_matched"])
        self.assertFalse(case["agreement"])

    def test_identically_wrong_peer_outputs_do_not_count_as_validated_agreement(
        self,
    ) -> None:
        method = next(
            item
            for item in self.methods
            if item.record == "PeerRecord" and item.field == "count" and not item.write
        )
        native = corpus.native_output(
            native_response(method, "int bad() { return self->count; }"), method
        )
        row = reference_row(method)
        row["text"] = "int independently_wrong() { return object_ref->count; }"
        case: dict[str, Any] = {
            "native_oracle_match": False,
            "native_expression": {"base": "field:count", "delta_u32": 0},
            "failures": [],
        }
        corpus.score_reference_case(case, row, method, native)
        self.assertTrue(case["raw_expression_equality"])
        self.assertFalse(case["reference_oracle_match"])
        self.assertFalse(case["agreement"])
        self.assertEqual(corpus.summarize([case], [])["counts"]["agreement"], 0)

    def test_reference_injected_this_or_wrong_record_is_rejected(self) -> None:
        for kind in ("extra", "record", "return"):
            row = reference_row(self.method)
            if kind == "extra":
                row["parameters"].append(copy.deepcopy(row["parameters"][0]))
            elif kind == "record":
                row["parameters"][0]["record_name"] = self.methods[-1].layout_name
            else:
                row["return_kind"] = "unsigned_integer"
            with self.subTest(kind=kind), self.assertRaises(corpus.CorpusError):
                corpus.validate_reference_method(row, self.method)

    def test_reference_identity_memory_and_settings_mismatch(self) -> None:
        request = {
            "input_sha256": "a" * 64,
            "memory_sha256": "b" * 64,
            "specifications": {},
            "scratch_root": str(FIXTURES),
        }
        mutations = {
            "input_sha256": "c" * 64,
            "memory_sha256": "c" * 64,
            "memory_validated": False,
            "layout_validated": False,
            "default_model": "__thiscall",
            "effective_options": {},
            "scratch_settings_owned": False,
        }
        for key, value in mutations.items():
            exported = reference_export(request, self.methods)
            exported[key] = value
            with self.subTest(key=key), self.assertRaises(corpus.CorpusError):
                corpus.reference_results(exported, request, self.methods)
        exported = reference_export(request, self.methods)
        exported["runtime_directories"]["application_cache"] = "/var/tmp/host-cache"
        with self.assertRaisesRegex(corpus.CorpusError, "escaped runner scratch"):
            corpus.reference_results(exported, request, self.methods)

    def test_reference_partial_results_keep_exact_identities_for_coverage(self) -> None:
        request = {
            "input_sha256": "a" * 64,
            "memory_sha256": "b" * 64,
            "specifications": {},
            "scratch_root": str(FIXTURES),
        }
        exported = reference_export(request, self.methods)
        exported["methods"].pop()
        results = corpus.reference_results(exported, request, self.methods)
        self.assertEqual(len(results), len(self.methods) - 1)
        self.assertNotIn(self.methods[-1].symbol, results)

    def test_reference_duplicate_or_wrong_va_results_fail(self) -> None:
        request = {
            "input_sha256": "a" * 64,
            "memory_sha256": "b" * 64,
            "specifications": {},
            "scratch_root": str(FIXTURES),
        }
        for kind in ("duplicate", "wrong_va"):
            exported = reference_export(request, self.methods)
            if kind == "duplicate":
                exported["methods"][-1] = copy.deepcopy(exported["methods"][0])
            else:
                exported["methods"][0]["address"] += 1
            with self.subTest(kind=kind), self.assertRaises(corpus.CorpusError):
                corpus.reference_results(exported, request, self.methods)


class MemoryTests(unittest.TestCase):
    def test_pt_load_file_bytes_zero_tail_and_permissions(self) -> None:
        data = tiny_elf()
        image = corpus.parse_elf(data)
        mapping = image.mappings[0]
        self.assertEqual(bytes.fromhex(mapping["hex_bytes"]), data)
        self.assertEqual(image.read_va(0x400280, 16), b"\0" * 16)
        self.assertEqual(
            (mapping["readable"], mapping["writable"], mapping["executable"]),
            (True, False, True),
        )
        self.assertEqual(image.exact_symbol("tiny").address, 0x400258)

    def test_memory_fingerprint_covers_permissions_zerotail_and_gaps(self) -> None:
        mappings = corpus.parse_elf(tiny_elf()).mappings
        original = corpus.memory_digest(mappings)
        for key, value in (("base", 0x500000), ("size", 657), ("writable", True)):
            changed = copy.deepcopy(mappings)
            changed[0][key] = value
            self.assertNotEqual(corpus.memory_digest(changed), original)
        changed = copy.deepcopy(mappings)
        changed[0]["hex_bytes"] = "ff" + changed[0]["hex_bytes"][2:]
        self.assertNotEqual(corpus.memory_digest(changed), original)

    def test_elf_oversized_memory_overlap_and_bad_symbol_table_fail(self) -> None:
        for kind in ("oversized", "overlap", "symbols", "truncated"):
            data = bytearray(tiny_elf())
            if kind == "oversized":
                struct.pack_into("<Q", data, 64 + 40, 1024 * 1024 + 1)
            elif kind == "overlap":
                struct.pack_into("<H", data, 56, 2)
                struct.pack_into(
                    "<IIQQQQQQ", data, 120, 1, 4, 0, 0x400100, 0, 16, 16, 1
                )
            elif kind == "symbols":
                struct.pack_into("<Q", data, 384 + 56, 8)
            else:
                data = data[:40]
            with self.subTest(kind=kind), self.assertRaises(corpus.CorpusError):
                corpus.parse_elf(bytes(data))


class ProcessTests(unittest.TestCase):
    def run_fake(
        self, body: str, payload: bytes = b"", **limits: Any
    ) -> corpus.ProcessResult:
        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            scratch = Path(directory)
            script = scratch / "fake.py"
            script.write_text(body)
            return corpus.run_process(
                [sys.executable, "-B", str(script)],
                scratch,
                limits.pop("timeout", 2),
                payload,
                dict(os.environ),
                **limits,
            )

    def test_fake_process_receives_stdin_without_unbounded_communicate(self) -> None:
        result = self.run_fake(
            "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])\n",
            b"a" * 100000,
        )
        self.assertIsNone(result.failure)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"a" * 100000)

    def test_stdout_and_stderr_are_separately_bounded(self) -> None:
        for stream in ("stdout", "stderr"):
            result = self.run_fake(
                f"import sys\nsys.{stream}.buffer.write(b'x' * 20000)\n",
                stdout_limit=1024,
                stderr_limit=1024,
            )
            self.assertEqual(result.failure, stream + "_limit")
            self.assertLessEqual(len(result.stdout), 1024)
            self.assertLessEqual(len(result.stderr), 1024)

    def test_external_deadline_covers_startup_and_reaps_leader(self) -> None:
        result = self.run_fake(
            "import signal\nprint('started', flush=True)\nsignal.pause()\n", timeout=0.3
        )
        self.assertEqual(result.failure, "external_deadline")
        self.assertIsNone(result.returncode)
        self.assertIn(result.guardian_returncode, (0, -signal.SIGKILL))

    def test_leader_exit_with_inherited_pipe_is_still_bounded(self) -> None:
        body = (
            "import subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c', 'import signal; signal.pause()'])\n"
        )
        result = self.run_fake(body, timeout=0.3)
        self.assertEqual(result.failure, "owned_descendants_outlived_leader")

    def test_group_kill_uses_group_not_only_child_pid(self) -> None:
        with (
            mock.patch.object(corpus, "owned_child_ended", return_value=False),
            mock.patch.object(corpus.os, "killpg") as kill,
        ):
            corpus.kill_owned_group(54321)
        kill.assert_called_once_with(54321, signal.SIGKILL)

    def test_unowned_or_already_reaped_pid_never_authorizes_group_signal(self) -> None:
        with (
            mock.patch.object(
                corpus, "owned_child_ended", side_effect=ChildProcessError
            ),
            mock.patch.object(corpus.os, "killpg") as kill,
            self.assertRaises(ChildProcessError),
        ):
            corpus.kill_owned_group(54321)
        kill.assert_not_called()

    def test_darwin_zombie_group_permission_is_accepted_only_after_fresh_no_live_proof(
        self,
    ) -> None:
        state: dict[str, Any] = {}
        calls: list[str] = []
        zombie = corpus.ProcessObservation(54321, 1, 54321, 0, "held-guardian", "Z")

        def signal_group(_group: int, _signal: int) -> None:
            calls.append("signal")
            raise PermissionError("Darwin zombie-only group")

        def reap(_pid: int, _timeout: float) -> int:
            calls.append("reap")
            return 0

        with (
            mock.patch.object(corpus, "owned_child_ended", return_value=True),
            mock.patch.object(corpus.os, "killpg", side_effect=signal_group),
            mock.patch.object(
                corpus, "sample_processes", return_value={54321: zombie}
            ) as snapshot,
            mock.patch.object(corpus, "reap_direct_child", side_effect=reap),
        ):
            self.assertTrue(corpus.reap_guardian(54321, state, Path("scratch")))
        snapshot.assert_called_once_with(Path("scratch"), 0.2)
        self.assertEqual(calls, ["signal", "reap"])
        self.assertNotIn("cleanup_error", state)
        live = corpus.ProcessObservation(54322, 54321, 54321, 1024, "live-child", "S")
        with (
            mock.patch.object(corpus, "owned_child_ended", return_value=True),
            mock.patch.object(
                corpus.os, "killpg", side_effect=PermissionError("live group")
            ),
            mock.patch.object(
                corpus, "sample_processes", return_value={54321: zombie, 54322: live}
            ),
            mock.patch.object(corpus, "reap_direct_child", return_value=0),
        ):
            self.assertFalse(corpus.reap_guardian(54321, state, Path("scratch")))
        self.assertIn("cleanup_error", state)

    def test_ended_guardian_before_group_registration_has_no_group_signal_authority(
        self,
    ) -> None:
        state: dict[str, Any] = {"group_registered": False, "start_released": False}
        with (
            mock.patch.object(corpus, "owned_child_ended", return_value=True),
            mock.patch.object(corpus, "kill_owned_group") as signal_group,
            mock.patch.object(corpus, "sample_processes") as snapshot,
            mock.patch.object(corpus, "reap_direct_child", return_value=126) as reap,
        ):
            self.assertTrue(corpus.reap_guardian(54321, state, Path("scratch")))
        signal_group.assert_not_called()
        snapshot.assert_not_called()
        reap.assert_called_once_with(54321, 1.0)
        self.assertEqual(state["guardian_returncode"], 126)
        self.assertNotIn("cleanup_error", state)

    def test_guardian_unexpected_exception_never_runs_parent_continuation(self) -> None:
        class UnrenderableError(Exception):
            def __str__(self) -> str:
                raise RuntimeError("error reporting also failed")

        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            scratch = Path(directory)
            escaped = scratch / "child-ran-parent-continuation"
            parent_pid = os.getpid()
            for exception in (
                RuntimeError("unexpected guardian fault"),
                UnrenderableError(),
            ):
                with self.subTest(exception=type(exception).__name__):
                    try:
                        with mock.patch.object(
                            corpus, "guardian_main", side_effect=exception
                        ):
                            result = corpus.run_process(
                                [sys.executable, "-c", "print('must not start')"],
                                scratch,
                                1,
                            )
                    finally:
                        if os.getpid() != parent_pid:
                            try:
                                escaped.touch()
                            finally:
                                os._exit(91)
                    self.assertFalse(escaped.exists())
                    self.assertTrue(
                        result.failure and result.failure.startswith("guardian_")
                    )
                    self.assertIsNone(result.returncode)
                    self.assertIsNone(result.max_observed_summed_rss_bytes)
                    self.assertEqual(result.metadata()["rss"]["status"], "unavailable")

    def test_observed_rss_is_summed_per_group_not_cumulative_children(self) -> None:
        self.assertEqual(corpus.parse_rss(" 42 3\n42 7\n11 9999\n", 42), 10 * 1024)
        with self.assertRaises(corpus.CorpusError):
            corpus.parse_rss("42 unknown", 42)
        result = captured({})
        metric = result.metadata()["rss"]
        self.assertEqual(metric["bytes"], 1024)
        self.assertIn("not a guaranteed or private peak", metric["limitation"])

    def test_absent_owned_group_is_not_a_zero_rss_observation(self) -> None:
        self.assertIsNone(corpus.parse_rss("11 9999\n", 42))
        self.assertIsNone(corpus.parse_rss("", 42))
        self.assertEqual(corpus.parse_rss("42 0\n", 42), 0)
        result = corpus.ProcessResult(
            ["fake"], 0, b"", b"", 0.01, None, 0, 1, rss_zero_samples=1
        )
        self.assertEqual(result.metadata()["rss"]["status"], "observed")
        self.assertEqual(result.metadata()["rss"]["zero_rss_owned_group_samples"], 1)

    def test_short_exit_with_no_observed_process_retains_unavailable_resource_status(
        self,
    ) -> None:
        with mock.patch.object(corpus, "sample_processes", return_value={}):
            result = self.run_fake("print('short exit')\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.failure, "rss_sampling_unavailable")
        self.assertIsNone(result.max_observed_summed_rss_bytes)
        self.assertEqual(result.rss_samples, 0)
        self.assertEqual(result.metadata()["rss"]["status"], "unavailable")

    def test_diagnostic_ancestry_survives_group_changes_without_authorizing_signals(
        self,
    ) -> None:
        root = corpus.ProcessObservation(42, 1, 42, 1024, "root-start", "S")
        child = corpus.ProcessObservation(43, 42, 43, 2048, "child-start", "S")
        known: dict[int, corpus.ProcessObservation] = {}
        current = corpus.update_owned_processes({42: root, 43: child}, 42, known)
        self.assertEqual(sum(item.rss_bytes for item in current.values()), 3072)
        orphan = corpus.ProcessObservation(43, 1, 43, 4096, "child-start", "S")
        current = corpus.update_owned_processes({43: orphan}, 42, known)
        self.assertEqual(current[43].rss_bytes, 4096)
        reused = corpus.ProcessObservation(43, 1, 43, 8192, "different-start", "S")
        self.assertEqual(corpus.update_owned_processes({43: reused}, 42, known), {})

    def test_actual_popen_preexec_stall_is_bounded_inside_owned_group(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            scratch = Path(directory)
            child_pid_path = scratch / "preexec.pid"
            marker = scratch / "must-not-exec"
            script = scratch / "launcher.py"
            target_code = f"from pathlib import Path; Path({str(marker)!r}).touch()"
            script.write_text(
                "import os, signal, subprocess, sys\nfrom pathlib import Path\n"
                "read_gate, write_gate = os.pipe()\n"
                "def barrier():\n"
                f"    Path({str(child_pid_path)!r}).write_text(str(os.getpid()))\n"
                "    os.read(read_gate, 1)\n"
                f"command = [sys.executable, '-c', {target_code!r}]\n"
                "child = subprocess.Popen(command, preexec_fn=barrier, pass_fds=(read_gate,))\n"
                "child.wait()\nsignal.pause()\n"
            )
            result = corpus.run_process(
                [sys.executable, "-B", str(script)],
                scratch,
                1,
                environment=dict(os.environ),
            )
            self.assertEqual(result.failure, "external_deadline")
            self.assertFalse(marker.exists())
            child_pid = int(child_pid_path.read_text())
            self.assertIsNotNone(result.owned_group)
            current = corpus.sample_processes(scratch, 1)
            self.assertTrue(
                child_pid not in current or current[child_pid].status.startswith("Z")
            )

    def test_separate_group_descendant_is_refused_not_signalled_and_exits_cooperatively(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            scratch = Path(directory)
            pid_path = scratch / "escaped.pid"
            script = scratch / "launcher.py"
            control_read, control_write = os.pipe()
            completion_read, completion_write = os.pipe()
            child_code = (
                "import os,select,sys; r=int(sys.argv[1]); w=int(sys.argv[2]); "
                "ready=select.select([r],[],[],3)[0]; "
                "value=os.read(r,1) if ready else b'timeout'; "
                "os.write(w,b'EOF' if value == b'' else b'BAD')"
            )
            try:
                os.set_inheritable(control_read, True)
                os.set_inheritable(completion_write, True)
                script.write_text(
                    "import subprocess,sys\nfrom pathlib import Path\n"
                    f"child=subprocess.Popen([sys.executable,'-c',{child_code!r},'{control_read}',"
                    f"'{completion_write}'],start_new_session=True,pass_fds=({control_read},{completion_write}))\n"
                    f"Path({str(pid_path)!r}).write_text(str(child.pid))\nchild.wait()\n"
                )
                real_killpg, real_kill = os.killpg, os.kill
                with (
                    mock.patch.object(
                        corpus.os, "killpg", wraps=real_killpg
                    ) as group_signals,
                    mock.patch.object(
                        corpus.os, "kill", wraps=real_kill
                    ) as pid_signals,
                ):
                    result = corpus.run_process(
                        [sys.executable, "-B", str(script)],
                        scratch,
                        2,
                        environment=dict(os.environ),
                    )
                child_pid = int(pid_path.read_text())
                self.assertEqual(
                    result.failure, "unsupported_separate_group_descendant"
                )
                self.assertIn(child_pid, result.observed_escaped_pids)
                self.assertTrue(
                    all(
                        call.args[0] == result.owned_group
                        for call in group_signals.call_args_list
                    )
                )
                self.assertTrue(
                    all(
                        call.args[0] != child_pid for call in pid_signals.call_args_list
                    )
                )
            finally:
                os.close(control_write)
                os.close(control_read)
                os.close(completion_write)
                try:
                    ready = select.select([completion_read], [], [], 4)[0]
                    self.assertTrue(ready, "cooperative escaped child did not complete")
                    self.assertEqual(os.read(completion_read, 3), b"EOF")
                finally:
                    os.close(completion_read)

    def test_catchable_signal_after_fork_before_handle_return_is_owned_and_reaped(
        self,
    ) -> None:
        real_fork = os.fork
        guardians: list[int] = []
        count = 0

        def fork_and_interrupt() -> int:
            nonlocal count
            count += 1
            initial = count == 1
            pid = real_fork()
            if pid > 0 and initial:
                guardians.append(pid)
                os.kill(os.getpid(), signal.SIGINT)
            return pid

        previous = signal.signal(signal.SIGINT, corpus.interrupt)
        try:
            with (
                mock.patch.object(corpus.os, "fork", side_effect=fork_and_interrupt),
                self.assertRaises(corpus.CorpusInterrupted),
            ):
                self.run_fake("import signal\nsignal.pause()\n")
        finally:
            signal.signal(signal.SIGINT, previous)
        self.assertEqual(len(guardians), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(guardians[0], os.WNOHANG)

    def test_nonzero_and_invalid_json_do_not_become_success(self) -> None:
        result = self.run_fake("import sys\nprint('{}')\nsys.exit(2)\n")
        with self.assertRaises(corpus.CorpusError):
            corpus.process_json(result, "fake")
        result = self.run_fake("print('not json')\n")
        with self.assertRaises(corpus.CorpusError):
            corpus.process_json(result, "fake")


class CliSelectionTests(unittest.TestCase):
    def test_physical_cli_copy_preserves_bytes_and_mode_without_copying_worker_sibling(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            original_bin = root / "original"
            original_bin.mkdir()
            original = original_bin / "rampage"
            contents = b"owned CLI copy fixture, never executed\n"
            original.write_bytes(contents)
            original.chmod(0o751)
            (original_bin / "rampage-worker").write_bytes(b"do not copy this sibling")
            expected = hashlib.sha256(contents).hexdigest()
            copied, copied_sha = corpus.copy_inline_cli(
                original, root / "scratch", expected
            )
            self.assertEqual(copied, root / "scratch/bin/c/rampage")
            self.assertEqual(copied.read_bytes(), contents)
            self.assertEqual(copied_sha, expected)
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o751)
            self.assertFalse(copied.is_symlink())
            self.assertFalse(copied.samefile(original))
            self.assertEqual(list(copied.parent.iterdir()), [copied])

    def test_cli_copy_refuses_changed_identity_and_over_budget_source(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            original = root / "rampage"
            original.write_bytes(b"owned bytes")
            original.chmod(0o700)
            with self.assertRaisesRegex(corpus.CorpusError, "recorded binary identity"):
                corpus.copy_inline_cli(original, root / "mismatch", "0" * 64)
            with (
                mock.patch.object(corpus, "MAX_EXECUTABLE", 4),
                self.assertRaisesRegex(corpus.CorpusError, "size/type bound"),
            ):
                corpus.copy_inline_cli(
                    original,
                    root / "oversized",
                    hashlib.sha256(b"owned bytes").hexdigest(),
                )
            self.assertFalse((root / "oversized").exists())

    def test_child_environment_removes_worker_override_instead_of_setting_one(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            with mock.patch.dict(
                os.environ,
                {"RAMPAGE_WORKER": "/outside/worker", "GHIDRA_INSTALL_DIR": ""},
            ):
                environment = corpus.child_environment(Path(directory))
            self.assertNotIn("RAMPAGE_WORKER", environment)


class OrchestrationTests(unittest.TestCase):
    def arguments(self, tools: Path | None = None) -> argparse.Namespace:
        tool_root = tools if tools is not None else Path("not-executed-tool-stubs")
        return argparse.Namespace(
            rampage=str(tool_root / "bin/rampage"),
            worker=str(tool_root / "bin/rampage-worker"),
            ghidra_headless=str(tool_root / "ghidra/support/analyzeHeadless"),
            java_home=str(tool_root / "jdk"),
            variant="dwarf5-o2",
            timeout=1,
        )

    def test_missing_tools_or_evidence_remain_in_six_case_denominator(self) -> None:
        with mock.patch.dict(os.environ, {"RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE": ""}):
            report = corpus.run_corpus(self.arguments())
        self.assertFalse(report["ok"])
        self.assertEqual(report["metrics"]["denominator"], 6)
        self.assertEqual(report["metrics"]["counts"]["refusals"], 6)

    def test_metrics_do_not_drop_partial_refused_or_missing_cases(self) -> None:
        cases = [
            {
                "admitted": True,
                "native_success": True,
                "reference_success": True,
                "settings_matched": True,
                "agreement": True,
                "failures": [],
            },
            {
                "admitted": True,
                "native_success": True,
                "failures": [{"stage": "reference"}],
            },
            {"failures": [{"stage": "gate"}]},
        ]
        metrics = corpus.summarize(
            cases, [{"category": "partial"}, {"category": "partial"}]
        )
        self.assertEqual(metrics["denominator"], 3)
        self.assertEqual(metrics["counts"]["selected"], 3)
        self.assertEqual(metrics["counts"]["agreement"], 1)
        self.assertEqual(metrics["counts"]["refusals"], 2)
        self.assertEqual(metrics["warning_categories"], {"partial": 2})

    def fake_run(
        self,
        reference_failure: bool = False,
        missing_result: bool = False,
        native_failure: bool = False,
        both_wrong_peer: bool = False,
        hostile_environment: bool = False,
        hostile_worker_override: bool = False,
    ) -> tuple[dict[str, Any], Path]:
        _oracle, methods, receipt, _layouts = accepted_inputs()
        image = corpus.ElfImage(
            b"owned test input",
            [
                {
                    "base": 0x401000,
                    "hex_bytes": "90" * 128,
                    "size": 128,
                    "readable": True,
                    "writable": False,
                    "executable": True,
                }
            ],
            [],
        )
        receipt["image_sha256"] = corpus.digest_bytes(image.data)
        owned_paths: list[Path] = []

        def run(
            command: list[str],
            scratch: Path,
            timeout: float,
            payload: bytes = b"",
            environment: dict[str, str] | None = None,
            **_limits: Any,
        ) -> corpus.ProcessResult:
            del timeout
            self.assertIsNotNone(environment)
            if environment is None:
                raise AssertionError("explicit process environment required")
            self.assertTrue(Path(environment["HOME"]).is_relative_to(scratch))
            self.assertNotIn("RAMPAGE_WORKER", environment)
            owned_paths.append(scratch)
            (scratch / "owned-sidecar").write_text("must be removed")
            if "import-debug-layouts" in command or "decompile" in command:
                cli = Path(command[0])
                self.assertEqual(cli, scratch / "bin/c/rampage")
                self.assertTrue(cli.is_file())
                self.assertFalse(cli.is_symlink())
                self.assertFalse(cli.samefile(original_cli))
                self.assertEqual(
                    corpus.file_digest(cli, corpus.MAX_EXECUTABLE), original_cli_sha
                )
                self.assertEqual(
                    stat.S_IMODE(cli.stat().st_mode),
                    stat.S_IMODE(original_cli.stat().st_mode),
                )
                self.assertEqual(list(cli.parent.iterdir()), [cli])
                self.assertFalse((cli.parent / "rampage-worker").exists())
            if "import-debug-layouts" in command:
                if "--apply" in command:
                    return captured(
                        {**receipt, "status": "applied", "whole_apply_succeeded": True},
                        command,
                    )
                return captured(receipt, command)
            if "decompile" in command:
                self.assertNotIn("--isolated", command)
                selected = next(
                    method
                    for method in methods
                    if hex(method.address) == command[command.index("--at") + 1]
                )
                output = native_response(selected)["output"]
                return captured(
                    {
                        "code": output["text"],
                        "structure": output["structure"],
                        "address": hex(selected.address),
                        "language_id": output["language_id"],
                        "recovery_status": "no_reported_issues",
                    },
                    command,
                )
            if "-postScript" in command:
                self.assertEqual(command[0], str(headless))
                self.assertEqual(environment["JAVA_HOME"], str(java_home))
                self.assertEqual(environment["JAVA_HOME_OVERRIDE"], str(java_home))
                for option in (
                    "_JAVA_OPTIONS",
                    "JDK_JAVA_OPTIONS",
                    "JAVA_OPTS",
                    "GHIDRA_JAVA_OPTIONS",
                    "GHIDRA_HEADLESS_JAVA_OPTIONS",
                ):
                    self.assertNotIn(option, environment)
                properties = dict(
                    item[2:].split("=", 1)
                    for item in shlex.split(environment["JAVA_TOOL_OPTIONS"])
                )
                self.assertEqual(
                    properties["application.settingsdir"], str(scratch / "gs")
                )
                self.assertEqual(
                    properties["application.cachedir"], str(scratch / "gc")
                )
                self.assertEqual(properties["application.tempdir"], str(scratch / "gt"))
                if reference_failure:
                    return corpus.ProcessResult(
                        command,
                        -9,
                        b"",
                        b"fake timeout",
                        1,
                        "external_deadline",
                        None,
                        0,
                    )
                index = command.index("ghidra_cpp_virtual_export.java")
                request = json.loads(Path(command[index + 1]).read_bytes())
                exported = reference_export(request, methods)
                if both_wrong_peer:
                    row = next(
                        item
                        for item in exported["methods"]
                        if item["symbol"] == "_ZN10PeerRecord9readCountEv"
                    )
                    row["text"] = "int wrong() { return object_ref->count; }"
                if missing_result:
                    exported["methods"].pop()
                Path(command[index + 2]).write_text(json.dumps(exported))
                return captured({}, command)
            request = json.loads(payload)
            self.assertEqual(command, [str(original_worker)])
            parse_error = fake_parse_types_error(request)
            if parse_error is not None:
                return captured(parse_error, command)
            selected = next(
                method
                for method in methods
                if method.address == request["decompile"]["address"]
            )
            if native_failure:
                return captured(
                    {"version": 4, "status": "error", "message": "fake native failure"},
                    command,
                )
            code = (
                "int wrong() { return self->count; }"
                if both_wrong_peer and selected.symbol == "_ZN10PeerRecord9readCountEv"
                else None
            )
            return captured(native_response(selected, code), command)

        with tempfile.TemporaryDirectory(
            prefix="cvtest", dir=temporary_parent()
        ) as directory:
            root = Path(directory).resolve()
            (root / "dwarf5-o2").mkdir()
            (root / "dwarf5-o2/records.debug.elf").write_bytes(image.data)
            arguments = self.arguments(root / "tools")
            original_cli = Path(arguments.rampage)
            original_worker = Path(arguments.worker)
            headless = Path(arguments.ghidra_headless)
            java_home = Path(arguments.java_home)
            stubs = {
                original_cli: b"owned fake CLI, never executed\n",
                original_worker: b"owned fake protocol-4 worker, never executed\n",
                headless: b"owned fake headless launcher, never executed\n",
                java_home / "bin/java": b"owned fake JDK launcher, never executed\n",
            }
            for path, contents in stubs.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                path.chmod(0o751)
            original_cli_sha = hashlib.sha256(stubs[original_cli]).hexdigest()
            environment = {
                "RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE": str(FIXTURES / "oracle.json"),
                "RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES": str(root),
                "TMPDIR": str(root),
                "GHIDRA_INSTALL_DIR": "",
            }
            if hostile_worker_override:
                environment["RAMPAGE_WORKER"] = "/outside/hostile-rampage-worker"
            if hostile_environment:
                for option in (
                    "JAVA_TOOL_OPTIONS",
                    "_JAVA_OPTIONS",
                    "JDK_JAVA_OPTIONS",
                    "JAVA_OPTS",
                    "GHIDRA_JAVA_OPTIONS",
                    "GHIDRA_HEADLESS_JAVA_OPTIONS",
                ):
                    environment[option] = (
                        "-Dapplication.cachedir=/var/tmp/hostile -Dapplication.settingsdir=/outside"
                    )
            with (
                mock.patch.dict(os.environ, environment),
                mock.patch.object(corpus, "parse_elf", return_value=image),
                mock.patch.object(corpus, "check_elf_oracle"),
                mock.patch.object(
                    corpus, "specification_identity", return_value=("c" * 64, {})
                ),
                mock.patch.object(corpus, "load_methods", return_value=methods),
                mock.patch.object(corpus, "run_process", side_effect=run),
            ):
                report = corpus.run_corpus(arguments)
            self.assertTrue(owned_paths, report.get("error"))
            self.assertTrue(all(not path.exists() for path in owned_paths))
            self.assertEqual(
                sorted(path.name for path in root.iterdir()), ["dwarf5-o2", "tools"]
            )
            for key, path in (
                ("cli_sha256", original_cli),
                ("worker_sha256", original_worker),
                ("headless_launcher_sha256", headless),
            ):
                self.assertEqual(
                    report["binaries"][key], hashlib.sha256(stubs[path]).hexdigest()
                )
            return report, owned_paths[0]

    def test_controlled_requests_and_cli_integration_are_separate(self) -> None:
        report, scratch = self.fake_run()
        self.assertFalse(scratch.exists())
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["metrics"]["counts"]["integration_success"], 6)
        self.assertEqual(report["metrics"]["counts"]["agreement"], 6)
        self.assertIn("reference_cold_batch_process", report)

    def test_hostile_inherited_headless_options_cannot_escape_scratch(self) -> None:
        report, scratch = self.fake_run(hostile_environment=True)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertFalse(scratch.exists())

    def test_hostile_worker_override_is_removed_but_standalone_worker_argv_is_preserved(
        self,
    ) -> None:
        report, scratch = self.fake_run(hostile_worker_override=True)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(
            report["execution_mode"], "inline_native_no_worker_override_or_sibling"
        )
        self.assertEqual(
            report["binaries"]["copied_cli_sha256"], report["binaries"]["cli_sha256"]
        )
        self.assertFalse(scratch.exists())

    def test_reference_oracle_coverage_survives_native_failure(self) -> None:
        report, _scratch = self.fake_run(native_failure=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["metrics"]["counts"]["reference_oracle_match"], 6)
        self.assertEqual(report["metrics"]["counts"]["settings_matched"], 0)

    def test_both_wrong_peer_results_are_raw_equal_but_not_validated_agreement(
        self,
    ) -> None:
        report, _scratch = self.fake_run(both_wrong_peer=True)
        case = next(
            item
            for item in report["cases"]
            if item["symbol"] == "_ZN10PeerRecord9readCountEv"
        )
        self.assertTrue(case["raw_expression_equality"])
        self.assertFalse(case["agreement"])
        self.assertFalse(report["ok"])

    def test_reference_failure_and_missing_results_cleanup_without_shrinking_denominator(
        self,
    ) -> None:
        for options in ({"reference_failure": True}, {"missing_result": True}):
            with self.subTest(options=options):
                report, scratch = self.fake_run(**options)
                self.assertFalse(report["ok"])
                self.assertFalse(scratch.exists())
                self.assertEqual(report["metrics"]["denominator"], 6)
                expected_refusals = 6 if options.get("reference_failure") else 1
                self.assertEqual(
                    report["metrics"]["counts"]["refusals"], expected_refusals
                )


if __name__ == "__main__":
    unittest.main()
