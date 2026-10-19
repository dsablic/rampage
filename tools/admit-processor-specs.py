"""Snapshot or verify the finite Ghidra 12.1.4 processor-data admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any

MAX_BYTES = 32 * 1024 * 1024
MAX_FILES = 4096
TAG = "Ghidra_12.1.4_build"
UPSTREAM = f"https://github.com/NationalSecurityAgency/ghidra/blob/{TAG}/"
FAMILIES = {
    "AVR8": ["Atmel/avr8.ldefs"],
    "8051": ["8051"],
    "MSP430": ["TI_MSP430"],
    "PIC": ["PIC"],
    "SuperH": ["SuperH", "SuperH4"],
    "V850": ["V850"],
    "TriCore": ["tricore"],
    "Xtensa": ["Xtensa"],
    "6502": ["6502"],
    "Z80": ["Z80"],
    "HCS12": ["HCS12"],
    "6805": ["MC6800/6805.ldefs"],
    "CR16": ["CR16"],
    "eBPF": ["eBPF"],
    "Loongarch": ["Loongarch"],
    "Hexagon": ["Hexagon"],
}
PILOTS = [
    ("MSP430", "TI_MSP430", "TI_MSP430", "TI_MSP430:LE:16:default", "default", 16),
    ("AVR8", "Atmel", "avr8", "avr8:LE:16:default", "gcc", 8),
    ("6502", "6502", "6502", "6502:LE:16:default", "default", 8),
]
NEXT_PROFILES = [
    ("8051", "8051", "8051", "8051:BE:16:default", "default", 8),
    ("PIC", "PIC", "pic16", "PIC-16:LE:16:PIC-16", "default", 8),
    ("SuperH", "SuperH", "superh", "SuperH:BE:32:SH-2", "default", 32),
    ("V850", "V850", "V850", "V850:LE:32:default", "default", 32),
    ("TriCore", "tricore", "tricore", "tricore:LE:32:default", "default", 32),
    ("Xtensa", "Xtensa", "xtensa", "Xtensa:LE:32:default", "default", 32),
    ("Z80", "Z80", "z80", "z80:LE:16:default", "default", 8),
    ("HCS12", "HCS12", "HCS12", "HCS-12:BE:24:default", "default", 16),
    ("6805", "MC6800", "6805", "6805:BE:16:default", "default", 8),
    ("CR16", "CR16", "CR16", "CR16C:LE:16:default", "default", 16),
    ("eBPF", "eBPF", "eBPF", "eBPF:LE:64:default", "default", 64),
    ("Loongarch", "Loongarch", "loongarch", "Loongarch:LE:64:lp64d", "default", 64),
    ("Hexagon", "Hexagon", "hexagon", "Hexagon:LE:32:default", "default", 32),
]
Selection = tuple[str, str, str, str, str, int]
PILOT_MANIFEST_SHA256 = (
    "b698b336d5e094d661181e113a7c72db7ef7c2679c68f5554d15e7e5882824f6"
)
PILOT_HELPER_SHA256 = "05aa632dd5de480293de511e30c0b5d06c209d161ae9a126fac07fdac46c9e57"
PILOT_TEST_SHA256 = "57e439b0cdab28a8f3bf5d7381522d978123d20be76e39e4506a9dbc5498dbce"
RESOURCE_DISPOSITION = "selected_profile_resource_admitted_siblings_dependencies_only_native_oracle_pending"
SYNTAX_REVIEW = (
    "Selected ldefs runtime siblings have bounded hashed syntax include closures."
)


class SnapshotBudget:
    def __init__(self) -> None:
        self.cached_bytes = 0
        self.cached_files = 0


def relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(p in ("", ".", "..") for p in value.split("/"))
    ):
        raise ValueError(f"Unsafe relative path: {value!r}")
    return path


def reject_symlinks(path: Path) -> None:
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError(f"Symlink refused: {ancestor}")


def stamp(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class Snapshot:
    def __init__(self, root: Path, budget: SnapshotBudget | None = None) -> None:
        self.root = root
        self.cache: dict[str, bytes] = {}
        self.cached_bytes = 0
        self.budget = budget if budget is not None else SnapshotBudget()

    def read(self, relative: str) -> bytes:
        if relative in self.cache:
            return self.cache[relative]
        if self.budget.cached_files >= MAX_FILES:
            raise ValueError("Snapshot file-count budget exceeded")
        remaining = MAX_BYTES - self.budget.cached_bytes
        path = self.root.joinpath(*relative_path(relative).parts)
        reject_symlinks(path)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb", buffering=0) as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
                    raise ValueError(f"Not a bounded regular file: {path}")
                if before.st_size > remaining:
                    raise ValueError(f"Snapshot aggregate byte budget exceeded: {path}")
                data = stream.read(remaining + 1)
                after = os.fstat(stream.fileno())
                current = path.lstat()
                if len(data) > remaining:
                    raise ValueError(f"Snapshot aggregate byte budget exceeded: {path}")
                if (
                    len(data) != before.st_size
                    or stamp(before) != stamp(after)
                    or stamp(after) != stamp(current)
                ):
                    raise ValueError(f"File changed during snapshot: {path}")
        except OSError as error:
            raise ValueError(f"Cannot snapshot {path}: {error}") from error
        self.cache[relative] = data
        self.cached_bytes += len(data)
        self.budget.cached_bytes += len(data)
        self.budget.cached_files += 1
        return data

    def record(self, relative: str) -> dict[str, Any]:
        data = self.read(relative)
        return {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }


def xml(data: bytes) -> ET.Element:
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("XML declarations with entities or DTDs are refused")
    return ET.fromstring(data)


def inventory(snapshot: Snapshot) -> list[dict[str, Any]]:
    result = []
    for family, modules in FAMILIES.items():
        definitions = []
        for module in modules:
            if "/" in module:
                name, filename = module.split("/")
                candidate = f"Ghidra/Processors/{name}/data/languages/{filename}"
                if (snapshot.root / candidate).exists():
                    definitions.append(candidate)
            else:
                directory = snapshot.root / f"Ghidra/Processors/{module}/data/languages"
                reject_symlinks(directory)
                definitions.extend(
                    str(p.relative_to(snapshot.root))
                    for p in sorted(directory.glob("*.ldefs"))
                )
        languages = []
        for path in definitions:
            base = PurePosixPath(path).parent
            for language in xml(snapshot.read(path)).findall("language"):
                sla = str(base / relative_path(language.attrib["slafile"]))
                syntax = str(PurePosixPath(sla).with_suffix(".slaspec"))
                languages.append(
                    {
                        "language_id": language.attrib["id"],
                        "ldefs_path": path,
                        "sla": snapshot.record(sla)
                        if (snapshot.root / sla).exists()
                        else None,
                        "installed_syntax_root": snapshot.record(syntax)
                        if (snapshot.root / syntax).exists()
                        else None,
                        "compiler_ids": [
                            c.attrib["id"] for c in language.findall("compiler")
                        ],
                    }
                )
        present = bool(languages) and all(item["sla"] is not None for item in languages)
        result.append(
            {
                "family": family,
                "modules": sorted({p.split("/")[2] for p in definitions}),
                "ldefs": [snapshot.record(p) for p in definitions],
                "languages": languages,
                "availability": "installed_compiled_sla_and_metadata"
                if present
                else "not_complete_in_installed_sdk",
                "disposition": (
                    "finite_pilot_data_admitted_oracle_pending"
                    if family in ("MSP430", "AVR8", "6502")
                    else "available_not_bundled_deferred_profile_and_oracle_review"
                    if present
                    else "installed_data_insufficient_upstream_availability_unknown"
                ),
                "source_availability": (
                    "installed_syntax_roots_present"
                    if languages and all(x["installed_syntax_root"] for x in languages)
                    else "some_or_all_syntax_roots_unknown"
                ),
                "syntax_closure_review": "Pilot modules only; other source root presence is not include-closure proof.",
            }
        )
    return result


def syntax_closure(snapshot: Snapshot, roots: set[str]) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    pending = sorted(roots)
    while pending:
        path = pending.pop()
        if path in records:
            continue
        if len(records) >= MAX_FILES:
            raise ValueError("Include-file budget exceeded")
        data = snapshot.read(path)
        includes = [
            str(PurePosixPath(path).parent / relative_path(name.decode("utf-8")))
            for name in re.findall(rb'^\s*@include\s+"([^"\r\n]+)"', data, re.MULTILINE)
        ]
        records[path] = {**snapshot.record(path), "includes": includes}
        pending.extend(includes)
    return [records[path] for path in sorted(records)]


def runtime_closure(
    snapshot: Snapshot,
    selections: list[Selection] = PILOTS,
) -> tuple[set[str], list[dict[str, str]], set[str]]:
    closure: set[str] = set()
    dependencies = []
    sources: set[str] = set()
    for _, module, stem, _, _, _ in selections:
        path = f"Ghidra/Processors/{module}/data/languages/{stem}.ldefs"
        closure.add(path)
        base = PurePosixPath(path).parent
        for language in xml(snapshot.read(path)).findall("language"):
            references = [
                (key, language.attrib[key]) for key in ("slafile", "processorspec")
            ]
            references.extend(
                ("compiler", c.attrib["spec"]) for c in language.findall("compiler")
            )
            references.extend(
                ("dwarf_register_mapping", e.attrib["name"])
                for e in language.findall("external_name")
                if e.attrib["tool"] == "DWARF.register.mapping.file"
            )
            manual = language.attrib.get("manualindexfile")
            if manual:
                if not manual.startswith("../manuals/"):
                    raise ValueError(f"Unexpected manual reference: {manual}")
                destination = str(
                    base.parent
                    / "manuals"
                    / relative_path(manual.removeprefix("../manuals/"))
                )
                closure.add(destination)
                dependencies.append(
                    {
                        "from": path,
                        "language_id": language.attrib["id"],
                        "kind": "optional_manual_index",
                        "to": destination,
                    }
                )
            for kind, name in references:
                destination = str(base / relative_path(name))
                closure.add(destination)
                dependencies.append(
                    {
                        "from": path,
                        "language_id": language.attrib["id"],
                        "kind": kind,
                        "to": destination,
                    }
                )
                if kind == "slafile":
                    sources.add(str(PurePosixPath(destination).with_suffix(".slaspec")))
        module_base = f"Ghidra/Processors/{module}"
        closure.update(
            f"{module_base}/{name}" for name in ("LICENSE.txt", "Module.manifest")
        )
        for item in (snapshot.root / module_base).rglob("*"):
            if item.is_file() and (
                "notice" in item.name.lower() or item.name.lower().startswith("license")
            ):
                closure.add(str(item.relative_to(snapshot.root)))
    return closure, dependencies, sources


def profiles(
    snapshot: Snapshot, closure: set[str], selections: list[Selection] = PILOTS
) -> list[dict[str, Any]]:
    result = []
    spaces = {
        "MSP430": [("RAM", 2, 1, True), ("register", 2, 1, False)],
        "AVR8": [
            ("code", 2, 2, True),
            ("mem", 2, 1, False),
            ("codebyte", 2, 1, False),
            ("register", 2, 1, False),
        ],
        "6502": [("RAM", 2, 1, True), ("register", 1, 1, False)],
        "8051": [
            ("CODE", 2, 1, True),
            ("RAM", 1, 1, False),
            ("INTMEM", 1, 1, False),
            ("EXTMEM", 2, 1, False),
            ("SFR", 1, 1, False),
            ("BITS", 1, 1, False),
            ("register", 1, 1, False),
        ],
        "PIC": [
            ("CODE", 2, 2, True),
            ("DATA", 2, 1, False),
            ("HWSTACK", 1, 2, False),
            ("register", 2, 1, False),
        ],
        "SuperH": [("ram", 4, 1, True), ("register", 4, 1, False)],
        "V850": [
            ("ram", 4, 1, True),
            ("register", 4, 1, False),
            ("sysreg", 2, 1, False),
        ],
        "TriCore": [("ram", 4, 1, True), ("register", 4, 1, False)],
        "Xtensa": [("ram", 4, 1, True), ("register", 4, 1, False)],
        "Z80": [("ram", 2, 1, True), ("io", 2, 1, False), ("register", 1, 1, False)],
        "HCS12": [("RAM", 3, 1, True), ("register", 2, 1, False)],
        "6805": [("RAM", 2, 1, True), ("register", 1, 1, False)],
        "CR16": [("ram", 4, 1, True), ("register", 2, 1, False)],
        "eBPF": [
            ("ram", 8, 1, True),
            ("register", 4, 1, False),
            ("syscall", 4, 1, False),
        ],
        "Loongarch": [
            ("ram", 8, 1, True),
            ("iocsr", 8, 1, False),
            ("register", 4, 1, False),
        ],
        "Hexagon": [("ram", 4, 1, True), ("register", 4, 1, False)],
    }
    for family, module, stem, language_id, compiler_id, cpu_width in selections:
        base = f"Ghidra/Processors/{module}/data/languages"
        ldefs = f"{base}/{stem}.ldefs"
        language = next(
            x
            for x in xml(snapshot.read(ldefs)).findall("language")
            if x.attrib["id"] == language_id
        )
        compiler = next(
            x for x in language.findall("compiler") if x.attrib["id"] == compiler_id
        )
        cspec = f"{base}/{compiler.attrib['spec']}"
        organization = xml(snapshot.read(cspec)).find("data_organization")
        sizes = (
            {}
            if organization is None
            else {
                x.tag: int(x.attrib["value"])
                for x in organization
                if x.tag.endswith("_size")
            }
        )
        result.append(
            {
                "family": family,
                "language_id": language_id,
                "compiler_id": compiler_id,
                "processor": language.attrib["processor"],
                "variant": language.attrib["variant"],
                "endian": language.attrib["endian"],
                "ldefs_size_bits": int(language.attrib["size"]),
                "cpu_register_width_bits": cpu_width,
                "ldefs_path": ldefs,
                "sla_path": f"{base}/{language.attrib['slafile']}",
                "pspec_path": f"{base}/{language.attrib['processorspec']}",
                "cspec_path": cspec,
                "runtime_file_closure": sorted(
                    p for p in closure if p.startswith(f"Ghidra/Processors/{module}/")
                ),
                "syntax_root": str(
                    PurePosixPath(base, language.attrib["slafile"]).with_suffix(
                        ".slaspec"
                    )
                ),
                "syntax_source_bundled": False,
                "address_spaces": [
                    {
                        "name": name,
                        "address_size_bytes": size,
                        "address_size_bits": size * 8,
                        "word_size_bytes": word,
                        "minimum_address": 0,
                        "default": default,
                        "source_kind": "installed_sleigh_syntax_review",
                        "sla_runtime_confirmation": None,
                    }
                    for name, size, word, default in spaces[family]
                ],
                "c_data_organization_explicit_sizes_bytes": sizes,
                "c_integer_size_bytes": sizes.get("integer_size"),
                "c_pointer_size_bytes": sizes.get("pointer_size"),
                "c_abi_status": "explicit_cspec_sizes"
                if sizes
                else "unknown_cspec_has_no_data_organization",
                "address_identity_rule": "Retain named space and native offset units; code:0 and mem:0 are distinct.",
                "wrapper_status": "metadata_only_not_processor_discovery_acceptance",
                "fixture_oracle": {
                    "status": "not_run",
                    "owned_byte_expectations_are_not_oracle_results": True,
                },
            }
        )
    return result


def resource_files(
    snapshot: Snapshot, closure: set[str], selections: list[Selection]
) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(closure):
        compiled = path.endswith(".sla")
        generated_license = path.endswith("/LICENSE.txt")
        source_path = (
            str(PurePosixPath(path).with_suffix(".slaspec")) if compiled else path
        )
        files.append(
            {
                **snapshot.record(path),
                "sdk_path": path,
                "upstream_source_url": None
                if generated_license
                else UPSTREAM + source_path,
                "upstream_module_url": UPSTREAM.replace("/blob/", "/tree/")
                + "/".join(path.split("/")[:3]),
                "distribution_resource_kind": (
                    "compiled_sleigh_data"
                    if compiled
                    else "generated_module_license_summary"
                    if generated_license
                    else "metadata_or_legal_text"
                ),
            }
        )
    for _, module, _, _, _, _ in selections:
        path = f"Ghidra/Processors/{module}/LICENSE"
        files.append(
            {
                **snapshot.record("LICENSE"),
                "path": path,
                "sdk_path": "LICENSE",
                "upstream_source_url": UPSTREAM + "LICENSE",
                "distribution_resource_kind": "upstream_license_text",
            }
        )
        closure.add(path)
    return sorted(files, key=lambda item: item["path"])


def create_manifest(snapshot: Snapshot) -> dict[str, Any]:
    application = snapshot.record("Ghidra/application.properties")
    properties = dict(
        line.split("=", 1)
        for line in snapshot.read(application["path"]).decode().splitlines()
        if "=" in line
    )
    if (
        properties.get("application.version"),
        properties.get("application.release.name"),
    ) != ("12.1.4", "PUBLIC"):
        raise ValueError("Expected installed Ghidra 12.1.4 PUBLIC")
    if f"application.revision.ghidra-{TAG}" not in properties:
        raise ValueError("Expected Ghidra build-tag property")
    available = inventory(snapshot)
    closure, dependencies, sources = runtime_closure(snapshot)
    syntax = syntax_closure(snapshot, sources)
    files = resource_files(snapshot, closure, PILOTS)
    total = sum(item["bytes"] for item in files)
    if total > MAX_BYTES or len(files) > MAX_FILES:
        raise ValueError("Pilot byte/file budget exceeded")
    return {
        "schema_version": 1,
        "status": "finite_three_profile_data_admission_oracle_pending",
        "source": {
            "kind": "installed_public_sdk_snapshot",
            "sdk_root_observed": str(snapshot.root),
            "version": "12.1.4",
            "release": "PUBLIC",
            "application_properties": application,
            "upstream_repository": "https://github.com/NationalSecurityAgency/ghidra",
            "upstream_tag": TAG,
            "resolved_upstream_commit": None,
            "sdk_archive_sha256": None,
            "authentication_limit": (
                "Hashes pin consumed installed bytes, not archive signature or commit authenticity."
            ),
            "license": "Apache-2.0",
            "network_used": False,
            "license_retention": "Exact SDK root LICENSE and module LICENSE.txt / Module.manifest retained.",
        },
        "limits": {
            "regular_file_bytes": MAX_BYTES,
            "pilot_total_bytes": MAX_BYTES,
            "include_files": MAX_FILES,
            "symlinks": False,
            "path_traversal": False,
            "archive_extraction": False,
        },
        "materialization": "Cache materializes already-compiled SLA; no lazy SLASPEC compiler is bundled or claimed.",
        "closure_policy": (
            "Original ldefs are byte-identical; sibling SLA, pspec, compiler specs, "
            "dwarf maps and manual indexes retained. "
            "Only three selected profiles admitted; sibling variants are dependencies, not accepted profiles."
        ),
        "manual_policy": "Optional manual indexes only; referenced PDFs are not consumed, fetched or bundled.",
        "syntax_policy": "Relative include closure hashed from consumed snapshots; syntax is not shipped or compiled.",
        "files": sorted(files, key=lambda x: x["path"]),
        "pilot_file_count": len(files),
        "pilot_total_bytes": total,
        "metadata_dependencies": dependencies,
        "installed_syntax_closure": syntax,
        "profiles": profiles(snapshot, closure),
        "requested_family_inventory": available,
        "acceptance_limits": [
            "No JVM oracle run or processor-discovery acceptance claim.",
            "No native-loader, benchmark, decompiler-success or architecture-parity claim.",
            "No compiler, installer, commercial executable, firmware or target execution included.",
        ],
    }


def review_legal(snapshot: Snapshot, closure: set[str]) -> list[dict[str, Any]]:
    reviews = []
    root_license = snapshot.record("LICENSE")
    if (
        root_license["sha256"]
        != "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
    ):
        raise ValueError("Resource batch rejected: unreviewed SDK root license")
    for family, module, _, language_id, _, _ in NEXT_PROFILES:
        prefix = f"Ghidra/Processors/{module}/"
        summary = snapshot.record(prefix + "LICENSE.txt")
        if (
            summary["sha256"]
            != "97229be970382866b88f5868b00382260ccbd44a0f65a21148582114fe18dc15"
        ):
            raise ValueError(
                f"Resource profile {family} rejected: unreviewed module license"
            )
        module_manifest = snapshot.record(prefix + "Module.manifest")
        if snapshot.read(module_manifest["path"]).strip():
            raise ValueError(
                f"Resource profile {family} rejected: unreviewed module manifest"
            )
        for path in closure:
            if not path.startswith(prefix):
                continue
            name = PurePosixPath(path).name
            if name in ("LICENSE.txt", "Module.manifest"):
                continue
            if PurePosixPath(path).suffix not in (
                ".sla",
                ".ldefs",
                ".pspec",
                ".cspec",
                ".dwarf",
                ".idx",
            ):
                raise ValueError(
                    f"Resource profile {family} rejected: unreviewed resource {path}"
                )
        reviews.append(
            {
                "family": family,
                "language_id": language_id,
                "license": "Apache-2.0",
                "module_license_summary": summary,
                "module_manifest": module_manifest,
                "root_license": root_license,
                "disposition": "reviewed_exact_known_Apache_summary_no_third_party_entries_or_custom_notice",
            }
        )
    return reviews


def cpu_evidence(snapshot: Snapshot, profile: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "8051": ("8051_main.sinc", "define register offset=0x00 size=1 [ R0"),
        "PIC": ("pic16.sinc", "define register offset=0x0003 size=1 [ W SkipNext ];"),
        "SuperH": ("superh.sinc", "define register offset=0 size=4 [r0 r1"),
        "V850": ("V850.sinc", "define register offset=0x0 size=0x4 [ r0"),
        "TriCore": ("tricore.sinc", "define register offset=0xFF00 size=4 [ d0 d1"),
        "Xtensa": ("xtensaArch.sinc", "define register offset=0x0000 size=4 [ a0 a1"),
        "Z80": ("z80.slaspec", "define register offset=0x00 size=1 [ F A"),
        "HCS12": ("HCS_HC12.sinc", "define register offset=0x00 size=2 [ D ];"),
        "6805": ("6805.slaspec", "define register offset=0x00 size=1 [ A X ];"),
        "CR16": ("CR16C.sinc", "define register offset=0 size=2 ["),
        "eBPF": ("eBPF.sinc", "define register offset=0 size=8 [ R0"),
        "Loongarch": (
            "loongarch_main.sinc",
            "define register offset=0x0 size=$(REGSIZE) [",
        ),
        "Hexagon": ("hexagon.slaspec", "define register offset=0 size=4 [ R0"),
    }
    filename, snippet = evidence[profile["family"]]
    path = str(PurePosixPath(profile["syntax_root"]).parent / filename)
    normalized = " ".join(snapshot.read(path).decode().split())
    if snippet not in normalized:
        raise ValueError(f"Scalar register evidence changed: {profile['family']}")
    size_match = re.search(r"size=(0x[0-9a-fA-F]+|\d+)", snippet)
    macros = []
    if size_match is not None:
        width = int(size_match.group(1), 0) * 8
    else:
        root = profile["syntax_root"]
        if (
            re.search(rb"^@define REGSIZE 8\s*$", snapshot.read(root), re.MULTILINE)
            is None
        ):
            raise ValueError("Loongarch scalar register macro evidence changed")
        macros.append({**snapshot.record(root), "definition": "@define REGSIZE 8"})
        width = 64
    if width != profile["cpu_register_width_bits"]:
        raise ValueError(
            f"Scalar register width disagrees with evidence: {profile['family']}"
        )
    return {
        "source": snapshot.record(path),
        "definition_prefix": snippet,
        "macro_evidence": macros,
        "interpretation": "scalar register width, not largest register or address width",
    }


def closure_summaries(
    snapshot: Snapshot, manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    files = {item["path"]: item for item in manifest["files"]}
    result = []
    for profile in manifest["profiles"]:
        digest = hashlib.sha256()
        total = 0
        paths = profile["runtime_file_closure"]
        for path in paths:
            data = snapshot.read(files[path]["sdk_path"])
            encoded = path.encode()
            digest.update(len(encoded).to_bytes(8, "little"))
            digest.update(encoded)
            digest.update(len(data).to_bytes(8, "little"))
            digest.update(data)
            total += len(data)
        result.append(
            {
                "family": profile["family"],
                "language_id": profile["language_id"],
                "compiler_id": profile["compiler_id"],
                "file_count": len(paths),
                "total_bytes": total,
                "sha256": digest.hexdigest(),
            }
        )
    return result


def extend_manifest(snapshot: Snapshot, original: dict[str, Any]) -> dict[str, Any]:
    if create_manifest(snapshot) != original:
        raise ValueError(
            "Frozen pilot source facts differ; refusing additive admission"
        )
    closure, dependencies, roots = runtime_closure(snapshot, NEXT_PROFILES)
    legal_reviews = review_legal(snapshot, closure)
    new_syntax = syntax_closure(snapshot, roots)
    new_files = resource_files(snapshot, closure, NEXT_PROFILES)
    added_profiles = profiles(snapshot, closure, NEXT_PROFILES)
    for profile in added_profiles:
        profile["cpu_width_evidence"] = cpu_evidence(snapshot, profile)
        organization = xml(snapshot.read(profile["cspec_path"])).find(
            "data_organization"
        )
        shift = None if organization is None else organization.find("pointer_shift")
        profile["c_pointer_shift"] = (
            None if shift is None else int(shift.attrib["value"])
        )
        profile["resource_admission_status"] = (
            "resource_admitted_pending_owned_oracle_and_native_bridge_comparison"
        )
        profile["native_backend_accepted"] = False
        profile["native_pcode_support"] = (
            "unknown_no_per_profile_owned_oracle_or_bridge_comparison_in_this_batch"
        )
        profile["abi_guard"] = (
            "decode_only_unknown_C_integer_or_pointer_size_no_host_defaults"
            if profile["c_integer_size_bytes"] is None
            or profile["c_pointer_size_bytes"] is None
            else "metadata_sizes_only_no_C_ABI_or_backend_acceptance"
        )
    all_files = sorted(original["files"] + new_files, key=lambda item: item["path"])
    if len({item["path"] for item in all_files}) != len(all_files):
        raise ValueError("Additive admission overlaps existing pilot assets")
    total = sum(item["bytes"] for item in all_files)
    if total > MAX_BYTES or len(all_files) > MAX_FILES:
        raise ValueError("Resource bundle aggregate byte/file budget exceeded")
    syntax_by_path = {
        item["path"]: item for item in original["installed_syntax_closure"] + new_syntax
    }
    requested = []
    for item in original["requested_family_inventory"]:
        if item["family"] not in {selection[0] for selection in NEXT_PROFILES}:
            requested.append(item)
        else:
            requested.append(
                {
                    **item,
                    "disposition": RESOURCE_DISPOSITION,
                    "syntax_closure_review": SYNTAX_REVIEW,
                }
            )
    manifest = {
        **original,
        "status": "finite_sixteen_profile_resource_admission_native_acceptance_separate",
        "files": all_files,
        "profiles": original["profiles"] + added_profiles,
        "metadata_dependencies": original["metadata_dependencies"] + dependencies,
        "installed_syntax_closure": [
            syntax_by_path[path] for path in sorted(syntax_by_path)
        ],
        "requested_family_inventory": requested,
        "resource_file_count": len(all_files),
        "resource_total_bytes": total,
        "resource_profile_count": len(original["profiles"]) + len(added_profiles),
        "closure_policy": (
            "Sixteen selected resource profiles only; original byte-identical ldefs sibling references are dependency "
            "closure, not additional admissions. New thirteen remain unregistered with the native bridge."
        ),
        "acceptance_limits": [
            "This resource batch executes no JVM oracle, native bridge, Cargo or target machine code.",
            (
                "New thirteen resource profiles require owned per-profile oracle/native comparison "
                "before backend acceptance."
            ),
            "Pilot native validation is parent-reported external evidence; original pilot records remain historical.",
            "No loader, decompiler, benchmark or complete architecture-parity acceptance is implied.",
        ],
        "admission_history": {
            "frozen_pilot_manifest_sha256": PILOT_MANIFEST_SHA256,
            "historical_helper_sha256": PILOT_HELPER_SHA256,
            "historical_test_source_sha256": PILOT_TEST_SHA256,
            "historical_pilot_file_count": original["pilot_file_count"],
            "historical_pilot_total_bytes": original["pilot_total_bytes"],
            "historical_status": original["status"],
            "historical_closure_policy": original["closure_policy"],
            "historical_acceptance_limits": original["acceptance_limits"],
            "provenance_limit": (
                "New generator source hashes belong to this extension attempt, not the historical pilot."
            ),
        },
        "new_batch_legal_review": legal_reviews,
        "closure_hash_format": (
            "SHA256 of sorted entries: u64le(path UTF-8 length), path, u64le(file length), file bytes"
        ),
    }
    manifest["resource_closure_summaries"] = closure_summaries(snapshot, manifest)
    return manifest


def verify(
    bundle: Path,
    sdk: Path | None,
    *,
    source: Snapshot | None = None,
    budget: SnapshotBudget | None = None,
) -> dict[str, Any]:
    if budget is None:
        budget = source.budget if source is not None else SnapshotBudget()
    if source is not None and source.budget is not budget:
        raise ValueError("Source and verification must share one aggregate budget")
    snapshot = Snapshot(bundle, budget)
    manifest = json.loads(snapshot.read("processor-admission.json"))
    files = manifest["files"]
    extended = "resource_profile_count" in manifest
    selections = PILOTS + NEXT_PROFILES if extended else PILOTS
    if len(files) > MAX_FILES or len(files) != manifest.get(
        "resource_file_count", manifest["pilot_file_count"]
    ):
        raise ValueError("Invalid file-count budget")
    expected: set[str] = set()
    total = 0
    if source is None and sdk is not None:
        source = Snapshot(sdk, budget)
    for item in files:
        path = item["path"]
        if path in expected:
            raise ValueError(f"Duplicate path: {path}")
        expected.add(path)
        if snapshot.record(path) != {
            key: item[key] for key in ("path", "bytes", "sha256")
        }:
            raise ValueError(f"Byte pin mismatch: {path}")
        total += item["bytes"]
        if total > MAX_BYTES:
            raise ValueError("Pilot byte budget exceeded")
        if source is not None and source.read(item["sdk_path"]) != snapshot.read(path):
            raise ValueError(f"SDK bytes differ: {path}")
    if total != manifest.get("resource_total_bytes", manifest["pilot_total_bytes"]):
        raise ValueError("Total byte count mismatch")
    for _, module, _, _, _, _ in selections:
        module_root = bundle / f"Ghidra/Processors/{module}"
        for path in module_root.rglob("*"):
            reject_symlinks(path)
            if not path.is_dir() and str(path.relative_to(bundle)) not in expected:
                raise ValueError(f"Unexpected module file: {path}")
    closure, dependencies, source_roots = runtime_closure(snapshot, selections)
    if closure != expected or dependencies != manifest["metadata_dependencies"]:
        raise ValueError("Runtime dependency closure mismatch")
    expected_profiles = profiles(snapshot, expected, selections)
    if len(expected_profiles) != len(manifest["profiles"]):
        raise ValueError("Selected profile count mismatch")
    for expected_profile, actual in zip(
        expected_profiles, manifest["profiles"], strict=True
    ):
        if any(actual.get(key) != value for key, value in expected_profile.items()):
            raise ValueError("Profile metadata mismatch")
    if not extended and expected_profiles != manifest["profiles"]:
        raise ValueError("Historical profile metadata mismatch")
    if extended:
        if manifest["resource_profile_count"] != len(PILOTS) + len(NEXT_PROFILES):
            raise ValueError("Unexpected resource admission roster")
        if (
            manifest["admission_history"]["frozen_pilot_manifest_sha256"]
            != PILOT_MANIFEST_SHA256
        ):
            raise ValueError("Historical pilot identity differs")
        for profile in manifest["profiles"][len(PILOTS) :]:
            organization = xml(snapshot.read(profile["cspec_path"])).find(
                "data_organization"
            )
            shift = None if organization is None else organization.find("pointer_shift")
            if profile.get("c_pointer_shift") != (
                None if shift is None else int(shift.attrib["value"])
            ):
                raise ValueError("Explicit pointer shift metadata mismatch")
            if profile.get("native_backend_accepted") is not False:
                raise ValueError(
                    "Resource admission cannot assert native backend acceptance"
                )
            if (
                profile.get("resource_admission_status")
                != "resource_admitted_pending_owned_oracle_and_native_bridge_comparison"
            ):
                raise ValueError(
                    "New profile must remain pending native oracle comparison"
                )
    syntax = manifest["installed_syntax_closure"]
    known = {item["path"] for item in syntax}
    if len(syntax) > MAX_FILES or any(
        ref not in known for item in syntax for ref in item["includes"]
    ):
        raise ValueError("Invalid source include closure")
    if source is not None:
        if (
            source.record("Ghidra/application.properties")
            != manifest["source"]["application_properties"]
        ):
            raise ValueError("SDK application properties differ")
        for item in syntax:
            if source.record(item["path"]) != {
                key: item[key] for key in ("path", "bytes", "sha256")
            }:
                raise ValueError(f"Syntax pin mismatch: {item['path']}")
        if syntax_closure(source, source_roots) != syntax:
            raise ValueError("Source include graph differs")
        observed_inventory = inventory(source)
        if extended:
            observed_inventory = [
                {
                    **item,
                    "disposition": RESOURCE_DISPOSITION,
                    "syntax_closure_review": SYNTAX_REVIEW,
                }
                if item["family"] in {selection[0] for selection in NEXT_PROFILES}
                else item
                for item in observed_inventory
            ]
            if (
                review_legal(
                    source,
                    closure - {f"Ghidra/Processors/{s[1]}/LICENSE" for s in selections},
                )
                != manifest["new_batch_legal_review"]
            ):
                raise ValueError("Legal review facts differ")
            if (
                closure_summaries(source, manifest)
                != manifest["resource_closure_summaries"]
            ):
                raise ValueError("Resource closure hashes differ")
            for profile in manifest["profiles"][len(PILOTS) :]:
                if cpu_evidence(source, profile) != profile["cpu_width_evidence"]:
                    raise ValueError("Scalar register source evidence differs")
        if observed_inventory != manifest["requested_family_inventory"]:
            raise ValueError("Installed inventory differs")
    return manifest


def stage_next(bundle: Path, sdk: Path, attempt: Path) -> dict[str, Any]:
    reject_symlinks(attempt)
    if attempt.resolve().is_relative_to(
        bundle.resolve()
    ) or attempt.resolve().is_relative_to(sdk.resolve()):
        raise ValueError("Staging attempt must be outside the original bundle and SDK")
    if attempt.exists():
        raise ValueError(f"Refusing to overwrite admission attempt: {attempt}")
    budget = SnapshotBudget()
    baseline_snapshot = Snapshot(bundle, budget)
    original_bytes = baseline_snapshot.read("processor-admission.json")
    if hashlib.sha256(original_bytes).hexdigest() != PILOT_MANIFEST_SHA256:
        raise ValueError("Expected the exact frozen three-profile manifest")
    original = verify(bundle, None, budget=budget)
    pilot_modules = {selection[1] for selection in PILOTS}
    existing_other = []
    for module in sorted((bundle / "Ghidra/Processors").iterdir()):
        if module.name in pilot_modules:
            continue
        for path in sorted(module.rglob("*")):
            reject_symlinks(path)
            if not path.is_dir():
                existing_other.append(
                    baseline_snapshot.record(str(path.relative_to(bundle)))
                )
    repository = Path(__file__).resolve().parents[1]
    generator_snapshot = Snapshot(repository, budget)
    generators = [
        generator_snapshot.record(path)
        for path in (
            "tools/admit-processor-specs.py",
            "tools/admit-processor-specs-test.py",
        )
    ]
    source = Snapshot(sdk, budget)
    manifest = extend_manifest(source, original)
    manifest["admission_history"]["extension_generator_source_snapshots"] = generators
    encoded_manifest = (json.dumps(manifest, indent=2) + "\n").encode()
    candidate = attempt / "bundle"
    reject_symlinks(candidate)
    attempt.mkdir(parents=True, exist_ok=False)
    candidate.mkdir()
    with (attempt / "frozen-pilot-manifest.json").open("xb") as stream:
        stream.write(original_bytes)
    for item in manifest["files"]:
        target = candidate.joinpath(*relative_path(item["path"]).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(source.read(item["sdk_path"]))
    with (candidate / "processor-admission.json").open("xb") as stream:
        stream.write(encoded_manifest)
    verified = verify(candidate, sdk, source=source, budget=budget)
    receipt = {
        "schema_version": 1,
        "status": "staged_candidate_verified_not_published_to_actual_specs",
        "baseline_manifest_sha256": PILOT_MANIFEST_SHA256,
        "candidate_manifest_sha256": hashlib.sha256(encoded_manifest).hexdigest(),
        "candidate_manifest_bytes": len(encoded_manifest),
        "candidate_bundle": str(candidate),
        "generator_source_snapshots": generators,
        "generator_provenance_limit": (
            "Current generator file snapshots identify this extension attempt only; "
            "they do not retroactively attest the frozen pilot or authenticate loaded Python code."
        ),
        "source": manifest["source"],
        "source_snapshot_file_count": len(source.cache),
        "source_snapshot_total_bytes": source.cached_bytes,
        "source_snapshot_entries": [
            source.record(path) for path in sorted(source.cache)
        ],
        "shared_run_consumed_file_count": budget.cached_files,
        "shared_run_consumed_bytes": budget.cached_bytes,
        "shared_run_byte_limit": MAX_BYTES,
        "budget_scope": (
            "One shared budget for SDK, baseline, generator snapshots and candidate verification; never reset."
        ),
        "resource_file_count": manifest["resource_file_count"],
        "resource_total_bytes": manifest["resource_total_bytes"],
        "added_file_count": manifest["resource_file_count"]
        - original["pilot_file_count"],
        "added_total_bytes": manifest["resource_total_bytes"]
        - original["pilot_total_bytes"],
        "resource_profile_count": manifest["resource_profile_count"],
        "new_profile_count": len(NEXT_PROFILES),
        "profile_closures": manifest["resource_closure_summaries"],
        "original_pilot_profile_records_unchanged": manifest["profiles"][: len(PILOTS)]
        == original["profiles"],
        "original_pilot_file_records_unchanged": all(
            item in manifest["files"] for item in original["files"]
        ),
        "existing_other_processor_file_count": len(existing_other),
        "existing_other_processor_total_bytes": sum(
            item["bytes"] for item in existing_other
        ),
        "existing_other_processor_files": existing_other,
        "new_profiles_native_acceptance": "pending_owned_oracle_and_native_bridge_comparison_no_whitelist_changes",
        "actual_specs_written": False,
        "network_used": False,
    }
    with (attempt / "source-receipt.json").open("x") as stream:
        stream.write(json.dumps(receipt, indent=2) + "\n")
    return verified


def publish_stage(bundle: Path, attempt: Path) -> dict[str, Any]:
    marker = attempt / "publication-receipt.json"
    reject_symlinks(marker)
    if marker.exists():
        raise ValueError("Refusing to overwrite an existing publication receipt")
    budget = SnapshotBudget()
    staged = Snapshot(attempt, budget)
    receipt = json.loads(staged.read("source-receipt.json"))
    candidate = attempt / "bundle"
    manifest_bytes = staged.read("bundle/processor-admission.json")
    if (
        hashlib.sha256(manifest_bytes).hexdigest()
        != receipt["candidate_manifest_sha256"]
    ):
        raise ValueError("Candidate manifest does not match the source receipt")
    if receipt["status"] != "staged_candidate_verified_not_published_to_actual_specs":
        raise ValueError("Expected a verified staged candidate receipt")
    repository = Path(__file__).resolve().parents[1]
    generators = Snapshot(repository, budget)
    for expected in receipt["generator_source_snapshots"]:
        if generators.record(expected["path"]) != expected:
            raise ValueError("Generator source changed since the staged attempt")
    manifest = verify(candidate, None, budget=budget)
    current = Snapshot(bundle, budget)
    current_bytes = current.read("processor-admission.json")
    if hashlib.sha256(current_bytes).hexdigest() != PILOT_MANIFEST_SHA256:
        raise ValueError("Publication requires the unchanged frozen pilot manifest")
    original = verify(bundle, None, budget=budget)
    for expected in receipt["existing_other_processor_files"]:
        if current.record(expected["path"]) != expected:
            raise ValueError(
                f"Existing non-pilot processor changed since staging: {expected['path']}"
            )
    if manifest["profiles"][: len(PILOTS)] != original["profiles"]:
        raise ValueError("Candidate changes historical pilot profile records")
    indexed = {item["path"]: item for item in manifest["files"]}
    for item in original["files"]:
        if indexed.get(item["path"]) != item:
            raise ValueError("Candidate changes a historical pilot file record")
    original_paths = {item["path"] for item in original["files"]}
    additions = [
        item for item in manifest["files"] if item["path"] not in original_paths
    ]
    for item in additions:
        path = bundle.joinpath(*relative_path(item["path"]).parts)
        reject_symlinks(path)
        if path.exists():
            raise ValueError(f"Refusing to overwrite new processor resource: {path}")
    for item in additions:
        data = staged.read("bundle/" + item["path"])
        if (
            len(data) != item["bytes"]
            or hashlib.sha256(data).hexdigest() != item["sha256"]
        ):
            raise ValueError(
                f"Staged resource changed before publication: {item['path']}"
            )
    temporary = bundle / "processor-admission.json.next"
    reject_symlinks(temporary)
    if temporary.exists():
        raise ValueError("Refusing to overwrite manifest publication temporary")
    for item in additions:
        path = bundle / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(staged.read("bundle/" + item["path"]))
    with temporary.open("xb") as stream:
        stream.write(manifest_bytes)
    temporary.replace(bundle / "processor-admission.json")
    verified = verify(bundle, None, budget=budget)
    final_snapshot = Snapshot(bundle, budget)
    for expected in receipt["existing_other_processor_files"]:
        if final_snapshot.record(expected["path"]) != expected:
            raise ValueError(
                f"Existing processor changed during publication: {expected['path']}"
            )
    publication = {
        "status": "resource_tree_published_and_verified_native_selectors_unchanged",
        "candidate_manifest_sha256": receipt["candidate_manifest_sha256"],
        "original_manifest_sha256": PILOT_MANIFEST_SHA256,
        "added_file_count": len(additions),
        "added_total_bytes": sum(item["bytes"] for item in additions),
        "resource_file_count": manifest["resource_file_count"],
        "resource_total_bytes": manifest["resource_total_bytes"],
        "shared_run_consumed_bytes": budget.cached_bytes,
        "shared_run_consumed_file_count": budget.cached_files,
        "sdk_read_again": False,
        "existing_other_processor_file_count_verified_unchanged": len(
            receipt["existing_other_processor_files"]
        ),
        "native_backend_acceptance": "not_changed_by_publication",
    }
    with marker.open("x") as stream:
        stream.write(json.dumps(publication, indent=2) + "\n")
    return verified


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "crates/rampage-decompiler/specs",
    )
    parser.add_argument(
        "--sdk",
        type=Path,
        help="Explicit public SDK; optional for bundle-only verification",
    )
    parser.add_argument(
        "--snapshot", action="store_true", help="Create new files only; requires --sdk"
    )
    parser.add_argument(
        "--stage-next",
        type=Path,
        help="Create-only thirteen-profile extension attempt directory; never writes --bundle",
    )
    parser.add_argument(
        "--publish-stage",
        type=Path,
        help="Publish a verified staged attempt into the unchanged pilot bundle; requires an external build lease",
    )
    arguments = parser.parse_args()
    try:
        if arguments.publish_stage is not None:
            if (
                arguments.sdk is not None
                or arguments.snapshot
                or arguments.stage_next is not None
            ):
                raise ValueError(
                    "--publish-stage excludes --sdk, --snapshot and --stage-next"
                )
            manifest = publish_stage(arguments.bundle, arguments.publish_stage)
            print(
                f"Published {manifest['resource_file_count']} files / "
                f"{manifest['resource_total_bytes']} bytes / 16 resources"
            )
            return
        if arguments.stage_next is not None:
            if arguments.sdk is None or arguments.snapshot:
                raise ValueError("--stage-next requires --sdk and excludes --snapshot")
            manifest = stage_next(
                arguments.bundle,
                arguments.sdk.resolve(strict=True),
                arguments.stage_next,
            )
            print(
                f"Staged {manifest['resource_file_count']} files / "
                f"{manifest['resource_total_bytes']} bytes / 16 resources"
            )
            return
        budget = SnapshotBudget()
        source = (
            Snapshot(arguments.sdk.resolve(strict=True), budget)
            if arguments.sdk
            else None
        )
        if arguments.snapshot:
            if arguments.sdk is None:
                raise ValueError("--snapshot requires --sdk")
            snapshot = source
            if snapshot is None:
                raise ValueError("SDK snapshot unavailable")
            manifest = create_manifest(snapshot)
            paths = [arguments.bundle / item["path"] for item in manifest["files"]]
            paths.append(arguments.bundle / "processor-admission.json")
            for path in paths:
                reject_symlinks(path)
                if path.exists():
                    raise ValueError(f"Refusing to overwrite: {path}")
            for item, path in zip(manifest["files"], paths):
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(snapshot.read(item["sdk_path"]))
            with paths[-1].open("x") as stream:
                stream.write(json.dumps(manifest, indent=2) + "\n")
        manifest = verify(
            arguments.bundle,
            arguments.sdk.resolve(strict=True) if arguments.sdk else None,
            source=source,
            budget=budget,
        )
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        parser.exit(1, f"Processor admission failed: {error}\n")
    print(
        f"Verified {manifest.get('resource_file_count', manifest['pilot_file_count'])} files / "
        f"{manifest.get('resource_total_bytes', manifest['pilot_total_bytes'])} bytes / "
        f"{len(manifest['profiles'])} resource profiles"
    )


if __name__ == "__main__":
    main()
