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
        "Vendored and adapted C++ decompiler compiled into crates/rampage-decompiler.\n"
        "The Ghidra 12.1.4 parser adaptations in context.cc bound instruction byte/bit\n"
        "extraction and zero-extend partial pattern-word lookahead. context.hh exposes\n"
        "pending context-commit evidence for conservative standalone decoding. Upstream\n"
        "Apache-2.0 headers and the complete license below are retained.",
        ["crates/rampage-decompiler/vendor/ghidra/LICENSE"],
    ),
    (
        "Arm A-profile machine-readable architecture specification (AARCHMRS)",
        "BSD-3-Clause",
        "https://developer.arm.com/Architectures/A-Profile%20Architecture",
        "AArch64 and AArch32 decoder tables in crates/rampage-arch are generated from this specification.",
        [
            "crates/rampage-arch/src/a64/LICENSE-ARM",
            "crates/rampage-arch/src/aarch32/LICENSE-ARM",
        ],
    ),
    (
        "musl minimal C and Linux/POSIX type declarations",
        "MIT",
        "https://git.musl-libc.org/cgit/musl/tree/?h=v1.2.5",
        "Selected type/import declarations adapted into bundled profiles; no libc implementation.",
        [
            "crates/rampage-api/resources/type-headers/LICENSE.musl",
            "crates/rampage-api/resources/type-headers/COPYRIGHT.musl",
        ],
    ),
    (
        "mingw-w64 minimal Windows type declarations",
        "ZPL-2.1 AND LicenseRef-Public-Domain",
        "https://github.com/mingw-w64/mingw-w64/tree/v12.0.0/mingw-w64-headers",
        "Selected type/import declarations adapted into bundled Windows profiles; not a Windows SDK.",
        [
            "crates/rampage-api/resources/type-headers/LICENSE.mingw-w64",
            "crates/rampage-api/resources/type-headers/DISCLAIMER.PD.mingw-w64",
        ],
    ),
]
COPYLEFT = re.compile(r"\b(A?GPL|LGPL|MPL|EPL|CDDL|EUPL|OSL|CECILL)", re.IGNORECASE)
# The pristine Apache-2.0 text (template appendix, no project copyright), used when a package ships no file.
APACHE_TEXT_PATH = "crates/rampage-decompiler/vendor/ghidra/LICENSE"

# License files some packages omit from the published crate, copied from their upstream repository.
YARA_X_LICENSE = """Copyright (c) 2024. The YARA-X Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (
INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
UPSTREAM_LICENSES = {
    "yara-x": ("LICENSE (from github.com/VirusTotal/yara-x)", YARA_X_LICENSE),
    "yara-x-parser": ("LICENSE (from github.com/VirusTotal/yara-x)", YARA_X_LICENSE),
}

MIT_TEMPLATE = """Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

BSL_TEXT = """Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""
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


def options(expression):
    return [o.strip() for o in re.split(r"\s+OR\s+|/", (expression or "").replace("(", " ").replace(")", " "))
            if o.strip()]


def fallback_files(package, siblings, same_license, repo):
    """License texts for a package that ships none, and how they were obtained. Preference: the upstream file,
    then the file of a package from the same repository under the identical license expression, then (for
    Apache-family licenses only) any shipped package's file under the identical expression, then the standard text
    of the elected license with holders from the package metadata. Expressions combining licenses with AND get no
    fallback: one text cannot stand in for several."""
    upstream = UPSTREAM_LICENSES.get(package["name"])
    if upstream:
        return [upstream], "upstream repository file"
    expression = package.get("license") or ""
    sibling = siblings.get((package.get("repository"), expression))
    if sibling:
        other, files = sibling
        return files, "file from " + other["name"] + " " + other["version"] + " (same repository and license)"
    if re.search(r"\bAND\b", expression):
        return [], None
    choices = options(expression)
    holders = "; ".join(package.get("authors") or []) or (
        "the " + package["name"] + " authors (" + (package.get("repository") or "no repository listed") + ")")
    apache = [choice for choice in choices if choice.split()[0] == "Apache-2.0"]
    if apache:
        # Apache texts carry no per-package copyright line, so another package's file under the identical
        # expression is exact, including a WITH exception such as LLVM-exception.
        identical = same_license.get(expression)
        if identical:
            other, files = identical
            return files, "file from " + other["name"] + " " + other["version"] + " (identical license expression)"
        if "Apache-2.0" not in apache:
            return [], None  # only offered WITH an exception whose text is not at hand
        text = read_text(os.path.join(repo, APACHE_TEXT_PATH))
        return [("standard Apache-2.0 text (elected; package ships none)", text)], "standard Apache-2.0 text"
    if "MIT" in choices:
        text = MIT_TEMPLATE.format(holders=holders)
        return [("standard MIT text (package ships none; holders from package metadata)", text)], \
            "standard MIT text"
    if "BSL-1.0" in choices:
        return [("standard BSL-1.0 text (package ships none)", BSL_TEXT)], "standard BSL-1.0 text"
    return [], None


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

    shipped = {package["id"]: license_files(package) for package in crates}
    siblings = {}
    same_license = {}
    for package in crates:
        files = shipped[package["id"]]
        if files:
            expression = package.get("license") or ""
            siblings.setdefault((package.get("repository"), expression), (package, files))
            same_license.setdefault(expression, (package, files))
    groups = defaultdict(list)
    no_files = []
    fallbacks = []
    for package in crates:
        files = shipped[package["id"]]
        if not files:
            files, source = fallback_files(package, siblings, same_license, repo)
            if source:
                fallbacks.append((package, source))
            else:
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
    out.append("for all target platforms, as resolved by Cargo.lock. License texts are reproduced verbatim")
    out.append("from each package; texts that are identical apart from whitespace are printed once and list")
    out.append("every crate that ships them. Packages that ship no license file are covered as listed at the")
    out.append("end of part 2.")
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
    if fallbacks:
        out.append("")
        out.append("The following crates ship no license file in their package. Their texts in part 3 come from")
        out.append("the source named here: the upstream repository's file, the file of a package from the same")
        out.append("repository under the identical license, or the standard text of the license elected from the")
        out.append("declared expression (Apache-2.0 when offered), with copyright holders from package metadata.")
        out.append("")
        for package, source in fallbacks:
            out.append("  " + package["name"] + " " + package["version"] + " (" + (package.get("license") or "?")
                       + "): " + source)
    if no_files:
        out.append("")
        out.append("The following crates ship no license file and no text could be supplied; only their declared")
        out.append("SPDX license is recorded here. The standard text of that license applies.")
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
    report += [f"  {count:4d}  {spdx}" for spdx, count in sorted(licenses.items(), key=lambda i: (-i[1], i[0]))]
    report.append("crates covered by a fallback text: " + str(len(fallbacks)))
    report.append("crates with no license text at all: " + (", ".join(
        p["name"] + " " + p["version"] for p in no_files) or "none"))
    flagged = [p["name"] + " " + p["version"] + " (" + p["license"] + ")" for p in crates
               if copyleft_only(p.get("license"))]
    report.append("copyleft-only crates: " + (", ".join(flagged) or "none"))
    sys.stderr.write("\n".join(report) + "\n")


if __name__ == "__main__":
    main()
