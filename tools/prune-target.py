#!/usr/bin/env python3
"""Delete superseded executables and stale incremental caches from the cargo target directory.

Run from the repository root. It refuses to run while a cargo build holds the target lock or a program started from
the target directory (such as a test binary) is running:

    python3 -I tools/prune-target.py            # report and delete
    python3 -I tools/prune-target.py --dry-run  # report only

Cargo names each test and binary executable `<name>-<hash>` in `<profile>/deps`. The hash changes whenever the
build configuration does (toolchain, profile settings, dependency versions, `-p` feature unification), and cargo
never deletes the old copy. Every workspace test executable statically links the whole dependency graph, so
superseded copies are most of the target directory's growth. This keeps the newest `--keep` executables per name and
crate root and deletes the rest with their `.d` files. A `bin` target and the unit tests of that `bin` share both,
and `-p` and `--workspace` builds can each have a current copy, so a live executable may still be deleted; cargo
relinks it on the next build.

Executables and incremental compilation caches untouched for `--days` are deleted too: that catches targets which
no longer exist, and a live one costs only a relink or a non-incremental rebuild of that crate.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict

HASHED = re.compile(r"^(?P<name>.+)-[0-9a-f]{16}$")


def build_running(profile_dir):
    lock = os.path.join(profile_dir, ".cargo-lock")
    if not os.path.exists(lock):
        return False
    try:
        result = subprocess.run(["lsof", "-t", lock], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("lsof is required to check for a running cargo build")
    return bool(result.stdout.strip())


def running_executables(target_dir):
    """Cargo releases its lock before running tests, so look for processes started from the target directory."""
    prefix = os.path.realpath(target_dir) + os.sep
    result = subprocess.run(["ps", "-Ao", "args="], capture_output=True, text=True, check=True)
    programs = {line.split(maxsplit=1)[0] for line in result.stdout.splitlines() if line.strip()}
    return sorted(program for program in programs if program.startswith(prefix))


def crate_root(executable):
    """The first source in cargo's dep-info file, which tells apart same-named targets of different crates."""
    try:
        with open(executable + ".d") as dep_info:
            sources = dep_info.readline().partition(": ")[2].split()
    except OSError:
        return None
    return sources[0] if sources else None


def superseded_executables(deps, keep, cutoff):
    by_target = defaultdict(list)
    for entry in os.scandir(deps):
        match = HASHED.match(entry.name)
        if match and entry.is_file(follow_symlinks=False) and os.access(entry.path, os.X_OK):
            target = (match["name"], crate_root(entry.path))
            by_target[target].append((entry.stat().st_mtime, entry.path))
    for copies in by_target.values():
        copies.sort(reverse=True)
        yield from (path for index, (mtime, path) in enumerate(copies) if index >= keep or mtime < cutoff)


def stale_incremental(incremental, cutoff):
    for entry in os.scandir(incremental):
        if entry.is_dir(follow_symlinks=False) and entry.stat().st_mtime < cutoff:
            yield entry.path


def tree_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    return sum(os.path.getsize(os.path.join(root, name)) for root, _, names in os.walk(path) for name in names)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target-dir", default=os.environ.get("CARGO_TARGET_DIR", "target"))
    parser.add_argument("--keep", type=int, default=3, help="executables to keep per target (default 3)")
    parser.add_argument("--days", type=float, default=7, help="age of executables and caches to delete (default 7)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.keep < 1:
        parser.error("--keep must be at least 1")

    profiles = [os.path.join(args.target_dir, name) for name in ("debug", "release")]
    profiles = [path for path in profiles if os.path.isdir(path)]
    busy = [path for path in profiles if build_running(path)]
    if busy:
        sys.exit(f"a cargo build holds the lock in {', '.join(busy)}; run again when it finishes")
    running = running_executables(args.target_dir)
    if running:
        sys.exit(f"{len(running)} programs from the target directory are running, e.g. {running[0]}; run again later")

    cutoff = time.time() - args.days * 86400
    doomed = []
    for profile in profiles:
        deps = os.path.join(profile, "deps")
        if os.path.isdir(deps):
            for path in superseded_executables(deps, args.keep, cutoff):
                doomed.append(path)
                if os.path.exists(path + ".d"):
                    doomed.append(path + ".d")
        incremental = os.path.join(profile, "incremental")
        if os.path.isdir(incremental):
            doomed.extend(stale_incremental(incremental, cutoff))

    freed = 0
    for path in doomed:
        freed += tree_size(path)
        if not args.dry_run:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
    verb = "would free" if args.dry_run else "freed"
    print(f"{len(doomed)} paths, {verb} {freed / 1e9:.1f} GB", file=sys.stderr)


if __name__ == "__main__":
    main()
