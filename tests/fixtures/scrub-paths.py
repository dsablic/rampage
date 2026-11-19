#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Blank build-machine directories out of freshly linked fixtures, keeping every byte offset.

    scrub-paths.py [--root DIR]... [--here DIR]... FILE...

Zig compiles its C runtime start files and compiler_rt itself, without the caller's -ffile-prefix-map, so their
debug info names the compilation directory (the build's working directory) and the zig installation. Each named
directory is overwritten in place, wherever it appears as a whole path prefix (followed by `/` or a NUL), with a
same-length no-op run, so no DWARF string offset moves:

    --root DIR  an absolute no-op: `/./.` (the root), so DIR/lib/libc/x.c reads /./././lib/libc/x.c
    --here DIR  a relative no-op: `./.` (that is, `.`), for the compilation directory

Afterwards no file may name any of the directories, `/Users/`, `/home/<name>/` or `/var/folders/` (a macOS
temporary directory); the script exits 1 if one does.
"""

import argparse
import os
import re
import sys

LOCAL = re.compile(rb"/Users/|/home/[a-z]|/var/folders/")


def absolute_noop(length):
    if length % 2 == 0:
        return b"/." * (length // 2)
    return b"//" + b"./" * ((length - 3) // 2) + b"."


def relative_noop(length):
    return b"./" * (length // 2) + (b"." if length % 2 else b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", action="append", default=[], help="directory to blank as an absolute no-op")
    parser.add_argument("--here", action="append", default=[], help="directory to blank as a relative no-op")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    replacements = []
    for directory, noop in [(d, absolute_noop) for d in args.root] + [(d, relative_noop) for d in args.here]:
        directory = os.path.normpath(directory).encode()
        if len(directory) < 3 or not directory.startswith(b"/"):
            parser.error(f"{directory.decode()} is not an absolute directory")
        blank = noop(len(directory))
        assert len(blank) == len(directory)
        replacements.append((directory, blank))
    # Longest first, so a directory inside another is blanked whole.
    replacements.sort(key=lambda pair: len(pair[0]), reverse=True)
    failed = False
    for name in args.files:
        with open(name, "rb") as handle:
            data = handle.read()
        for directory, blank in replacements:
            data = re.sub(re.escape(directory) + rb"(?=[/\0])", blank, data)
        with open(name, "wb") as handle:
            handle.write(data)
        left = [directory for directory, _ in replacements if directory in data]
        if LOCAL.search(data) or left:
            print(f"{name} still holds a local path", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
