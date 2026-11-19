#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Find build-machine paths in files, and blank them out of freshly linked fixtures keeping every byte offset.

    scrub-paths.py --check [--files-from LIST | FILE...]
    scrub-paths.py [--zig-install DIR] [--root DIR]... [--here DIR]... FILE...

A local path is /Users/<name>, /home/<name>/ (the generic /home/user/ excepted: tests use it as made-up data),
/var/folders/ or /private/tmp/ (macOS temporary directories) or C:\\Users\\ (any case). --check only reports the
files holding one and exits 1 if any does; --files-from reads NUL-separated names (`-` for stdin), as
`git ls-files -z` prints them. This is the one definition the build scripts and tools/ci/check-fixture-paths.sh
share.

Without --check, each FILE is rewritten. Zig compiles its C runtime start files and compiler_rt itself, without the
caller's -ffile-prefix-map, so their debug info names the compilation directory (the build's working directory),
the zig installation and the zig cache. Each named directory is overwritten in place with a same-length no-op run,
so no DWARF string offset moves:

    --zig-install DIR  the zig installation: its parent directory is blanked to `/./.` (the root), only where it
                       is directly followed by /<DIR's own name>/, so /x/y/zig-macos-0.17.0/lib/libc/a.c reads
                       /./././zig-macos-0.17.0/lib/libc/a.c and nothing else under the parent is touched
    --root DIR         blanked to `/./.` wherever it is followed by `/` or a NUL (a private cache directory)
    --here DIR         blanked to `./.` (that is, `.`) likewise, for the compilation directory

Every directory blanked must be absolute, at least two components deep and not a system directory, so a zig
installed in /usr/bin or under /opt/homebrew/bin is refused rather than blanking /usr or /opt/homebrew everywhere.
Afterwards no file may name any of the directories or a local path; the script exits 1 if one does.
"""

import argparse
import os
import re
import sys

LOCAL = re.compile(
    rb"/Users/[A-Za-z0-9_.-]|/home/(?!user/)[a-z][a-z0-9_.-]*/|/var/folders/|/private/tmp/|(?i:c:\\users\\)"
)
SYSTEM = {b"/usr", b"/usr/local", b"/usr/lib", b"/opt", b"/opt/homebrew", b"/opt/local", b"/bin", b"/lib",
          b"/nix", b"/nix/store", b"/private", b"/private/var", b"/var", b"/tmp", b"/Users", b"/home"}


def absolute_noop(length):
    if length % 2 == 0:
        return b"/." * (length // 2)
    return b"//" + b"./" * ((length - 3) // 2) + b"."


def relative_noop(length):
    return b"./" * (length // 2) + (b"." if length % 2 else b"")


def directory(parser, text):
    path = os.path.normpath(text).encode()
    if not path.startswith(b"/") or len([part for part in path.split(b"/") if part]) < 2 or path in SYSTEM:
        parser.error(f"refusing to blank {text}: not an absolute, private directory at least two components deep")
    return path


def local_path(data):
    match = LOCAL.search(data)
    if match is None:
        return None
    end = min(len(data), match.start() + 80)
    return data[match.start():end].split(b"\0")[0].split(b"\n")[0].decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="only report files holding a local path")
    parser.add_argument("--files-from", help="NUL-separated file names, `-` for stdin")
    parser.add_argument("--zig-install", help="zig installation whose parent is blanked before its own name")
    parser.add_argument("--root", action="append", default=[], help="directory to blank as an absolute no-op")
    parser.add_argument("--here", action="append", default=[], help="directory to blank as a relative no-op")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()
    files = list(args.files)
    if args.files_from:
        stream = sys.stdin.buffer if args.files_from == "-" else open(args.files_from, "rb")
        files += [name.decode() for name in stream.read().split(b"\0") if name]
    if not files:
        parser.error("no files")
    replacements = []
    if not args.check:
        if args.zig_install:
            install = os.path.normpath(args.zig_install)
            parent = directory(parser, os.path.dirname(install))
            name = re.escape(os.path.basename(install).encode())
            replacements.append((parent, re.escape(parent) + rb"(?=/" + name + rb"/)", absolute_noop(len(parent))))
        for text, noop in [(d, absolute_noop) for d in args.root] + [(d, relative_noop) for d in args.here]:
            path = directory(parser, text)
            replacements.append((path, re.escape(path) + rb"(?=[/\0])", noop(len(path))))
        # Longest first, so a directory inside another is blanked whole.
        replacements.sort(key=lambda replacement: len(replacement[0]), reverse=True)
    elif args.zig_install or args.root or args.here:
        parser.error("--check rewrites nothing; it takes no directories")
    found = 0
    for name in files:
        with open(name, "rb") as handle:
            data = handle.read()
        if replacements:
            for path, pattern, blank in replacements:
                assert len(blank) == len(path)
                data = re.sub(pattern, blank, data)
            with open(name, "wb") as handle:
                handle.write(data)
        left = local_path(data) or next((path.decode() for path, _, _ in replacements if path in data), None)
        if left is not None:
            print(f"{name} holds a local path: {left}", file=sys.stderr)
            found += 1
    if found:
        print(f"{found} file(s) hold a local path", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
