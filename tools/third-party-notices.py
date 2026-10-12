#!/usr/bin/env python3
"""Generate THIRD-PARTY-NOTICES for Rampage binary distributions.

Run from the repository root:

    python3 -I tools/third-party-notices.py

Shipped crates are the normal (non-dev, non-build) dependencies of the release binaries, for every target
platform, as resolved by `cargo tree`. Proc-macro crates run only at compile time and are not linked into the
binaries, so they (and anything reachable only through them) are left out. Workspace crates are left out too.
Package details and license files come from `cargo metadata`. A summary goes to stderr.
"""

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

BINARY_PACKAGES = ["rampage-cli", "rampage-worker", "rampage-ui"]
OUTPUT_NAME = "THIRD-PARTY-NOTICES"
REGENERATE = "python3 -I tools/third-party-notices.py"
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")
# Native sources bundled inside a crate's package and compiled into the binary, with their own license files.
BUNDLED_LICENSES = {
    "capstone-sys": ["capstone/LICENSE.TXT", "capstone/LICENSE_LLVM.TXT"],
    "epaint_default_fonts": ["fonts/Hack-Regular.txt", "fonts/OFL.txt", "fonts/UFL.txt",
                             "fonts/emoji-icon-font-mit-license.txt"],
}
VENDORED = [
    (
        "Ghidra decompiler",
        "Apache-2.0",
        "https://github.com/NationalSecurityAgency/ghidra",
        "Vendored and adapted C++ decompiler compiled into crates/rampage-decompiler.",
        ["crates/rampage-decompiler/vendor/ghidra/LICENSE"],
    ),
    (
        "Arm A-profile machine-readable architecture specification (AARCHMRS)",
        "BSD-3-Clause",
        "https://developer.arm.com/Architectures/A-Profile%20Architecture",
        "AArch64 and AArch32 decoder tables in crates/rampage-arch are generated from this specification.",
        ["crates/rampage-arch/src/a64/LICENSE-ARM", "crates/rampage-arch/src/aarch32/LICENSE-ARM"],
    ),
]
COPYLEFT = re.compile(r"\b(A?GPL|LGPL|MPL|EPL|CDDL|EUPL|OSL|CECILL)", re.IGNORECASE)
RULE = "=" * 78
SUBRULE = "-" * 78


def cargo(args):
    env = dict(os.environ, CARGO_TERM_COLOR="never")
    return subprocess.run(["cargo", *args], check=True, capture_output=True, text=True, env=env).stdout


def shipped_ids():
    args = ["tree", "--locked", "-e", "normal,no-proc-macro", "--target", "all", "--prefix", "none"]
    args += ["--format", "{p}"]
    for package in BINARY_PACKAGES:
        args += ["-p", package]
    found = set()
    for line in cargo(args).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            found.add((parts[0], parts[1][1:]))
    return found


def read_text(path):
    with open(path, "rb") as handle:
        text = handle.read().decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n").strip("\n") + "\n"


def license_files(package):
    root = os.path.dirname(package["manifest_path"])
    names = []
    for entry in sorted(os.listdir(root)):
        if not entry.upper().startswith(LICENSE_PREFIXES):
            continue
        path = os.path.join(root, entry)
        if os.path.isfile(path):
            names.append(entry)
        elif os.path.isdir(path):
            names += [entry + "/" + inner for inner in sorted(os.listdir(path))
                      if os.path.isfile(os.path.join(path, inner))]
    declared = package.get("license_file")
    if declared and os.path.normpath(declared) not in [os.path.normpath(name) for name in names]:
        names.append(declared)
    for extra in BUNDLED_LICENSES.get(package["name"], []):
        if os.path.isfile(os.path.join(root, extra)) and extra not in names:
            names.append(extra)
    return [(name, read_text(os.path.join(root, name))) for name in names]


def copyleft_only(expression):
    if not expression or not COPYLEFT.search(expression):
        return False
    alternatives = re.split(r"\s+OR\s+|/", expression.replace("(", " ").replace(")", " "))
    return all(COPYLEFT.search(option) for option in alternatives if option.strip())


def main():
    repo = os.getcwd()
    output = os.path.join(repo, OUTPUT_NAME)
    if len(sys.argv) == 3 and sys.argv[1] == "-o":
        output = sys.argv[2]
    elif len(sys.argv) != 1:
        sys.exit("usage: " + REGENERATE + " [-o PATH|-]")

    metadata = json.loads(cargo(["metadata", "--locked", "--format-version", "1"]))
    members = set(metadata["workspace_members"])
    by_key = {(p["name"], p["version"]): p for p in metadata["packages"]}
    wanted = shipped_ids()
    missing = sorted(key for key in wanted if key not in by_key)
    if missing:
        sys.exit("packages from cargo tree not found in cargo metadata: " + repr(missing))
    crates = sorted((by_key[key] for key in wanted if by_key[key]["id"] not in members),
                    key=lambda p: (p["name"], p["version"]))

    groups = defaultdict(list)
    no_files = []
    for package in crates:
        files = license_files(package)
        if not files:
            no_files.append(package)
        for name, text in files:
            groups[" ".join(text.split())].append((package, name, text))
    ordered = sorted(((owners[0][2], [(p, n) for p, n, _ in owners]) for owners in groups.values()),
                     key=lambda item: [(p["name"], p["version"], n) for p, n in item[1]])
    text_ids = {}
    for number, (text, owners) in enumerate(ordered, 1):
        for package, _ in owners:
            text_ids.setdefault(package["id"], []).append(number)

    out = []
    out.append("THIRD-PARTY NOTICES")
    out.append("")
    out.append("Rampage is licensed under the Apache License, Version 2.0 (see LICENSE and NOTICE).")
    out.append("Its binary distributions (rampage, rampage-worker, rampage-ui) include the third-party")
    out.append("components listed below, each under its own license.")
    out.append("")
    out.append("This file is generated. Do not edit it by hand. To regenerate, from the repository root:")
    out.append("")
    out.append("    " + REGENERATE)
    out.append("")
    out.append("Rust crates are the normal (non-dev, non-build, non-proc-macro) dependencies of the")
    out.append("binary packages " + ", ".join(BINARY_PACKAGES) + ",")
    out.append("for all target platforms, as resolved by Cargo.lock. License texts are reproduced verbatim from each package; texts that are")
    out.append("identical apart from whitespace are printed once and list every crate that ships them.")
    out.append("")
    out.append(RULE)
    out.append("PART 1. VENDORED COMPONENTS")
    out.append(RULE)
    for title, spdx, url, note, paths in VENDORED:
        out.append("")
        out.append(title)
        out.append("License: " + spdx)
        out.append("Source: " + url)
        out.append(note)
        for path in paths:
            out.append("")
            out.append(SUBRULE)
            out.append(path)
            out.append(SUBRULE)
            out.append(read_text(os.path.join(repo, path)).rstrip("\n"))
    out.append("")
    out.append(RULE)
    out.append("PART 2. RUST CRATES (" + str(len(crates)) + ")")
    out.append(RULE)
    out.append("")
    out.append("Format: name version | license | repository | license texts in part 3")
    out.append("")
    for package in crates:
        ids = text_ids.get(package["id"])
        where = ", ".join("#" + str(n) for n in ids) if ids else "none: package ships no license file"
        fields = [package["name"] + " " + package["version"], package.get("license") or "(no SPDX license field)",
                  package.get("repository") or "(no repository)", where]
        out.append(" | ".join(fields))
    if no_files:
        out.append("")
        out.append("The following crates ship no license file in their package; only their declared SPDX")
        out.append("license is recorded here. The standard text of that license applies.")
        out.append("")
        for package in no_files:
            out.append("  " + package["name"] + " " + package["version"] + ": " + (package.get("license") or "?"))
    out.append("")
    out.append(RULE)
    out.append("PART 3. LICENSE TEXTS (" + str(len(ordered)) + ")")
    out.append(RULE)
    for number, (text, owners) in enumerate(ordered, 1):
        out.append("")
        out.append(SUBRULE)
        out.append("#" + str(number) + " used by:")
        for package, name in owners:
            out.append("  " + package["name"] + " " + package["version"] + " (" + name + ")")
        out.append(SUBRULE)
        out.append(text.rstrip("\n"))
    content = "\n".join(out) + "\n"

    if output == "-":
        sys.stdout.write(content)
    else:
        with open(output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)

    licenses = Counter(p.get("license") or "(none)" for p in crates)
    report = ["shipped crates: " + str(len(crates)), "distinct license texts: " + str(len(ordered)),
              "license distribution:"]
    report += ["  %4d  %s" % (count, spdx) for spdx, count in sorted(licenses.items(), key=lambda i: (-i[1], i[0]))]
    report.append("crates without a license file: " + (", ".join(
        p["name"] + " " + p["version"] for p in no_files) or "none"))
    flagged = [p["name"] + " " + p["version"] + " (" + p["license"] + ")" for p in crates
               if copyleft_only(p.get("license"))]
    report.append("copyleft-only crates: " + (", ".join(flagged) or "none"))
    sys.stderr.write("\n".join(report) + "\n")


if __name__ == "__main__":
    main()
