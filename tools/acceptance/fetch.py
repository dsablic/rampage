#!/usr/bin/env python3
"""Download the acceptance inputs listed in inputs.json and verify each SHA-256.

Files land in target/acceptance/inputs (or --out). Nothing is written inside the source tree outside target/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
USER_AGENT = "acceptance-fetch/1"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    partial = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(request, timeout=300) as response, partial.open("wb") as out:
        for block in iter(lambda: response.read(1 << 20), b""):
            out.write(block)
    partial.replace(dest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=HERE / "inputs.json")
    parser.add_argument("--out", type=Path, default=REPO / "target" / "acceptance" / "inputs")
    parser.add_argument("--only", action="append", default=[], help="input id; repeatable")
    args = parser.parse_args()

    inputs = json.loads(args.manifest.read_text())["inputs"]
    unknown = set(args.only) - {item["id"] for item in inputs}
    if unknown:
        print(f"unknown input ids: {sorted(unknown)}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)

    failed = 0
    for item in inputs:
        if args.only and item["id"] not in args.only:
            continue
        dest = args.out / item["file"]
        if dest.exists() and sha256_of(dest) == item["sha256"]:
            print(f"ok       {item['id']}")
            continue
        try:
            download(item["url"], dest)
        except OSError as error:
            print(f"FAILED   {item['id']}: {error}", file=sys.stderr)
            failed += 1
            continue
        actual = sha256_of(dest)
        if actual != item["sha256"]:
            dest.unlink()
            print(f"MISMATCH {item['id']}: got {actual}, expected {item['sha256']}", file=sys.stderr)
            failed += 1
            continue
        print(f"fetched  {item['id']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
