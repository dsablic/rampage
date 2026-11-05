"""Measure each server's open-and-analysis time for one file outside any agent run, for the scale tasks' report.

rampage: `rampage --json function list FILE` from the release build, which loads the image and runs the same
discovery and analysis its MCP server does on open. REA: `rea decompile FILE --procedure NAME --provider ghidra`,
whose first Ghidra-backed query waits for Ghidra's import and auto-analysis of a fresh copy (no project cache), with
the same REA_GHIDRA_STARTUP_TIMEOUT_MS the benchmark gives the REA server. Each measurement copies the file into
a fresh directory, as the benchmark does per run.

Usage: python3 -I tools/agent-bench/v2/time-open.py FILE PROCEDURE OUT.json [--repeat N] [--rea-timeout-ms MS]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GHIDRA = "/opt/homebrew/Cellar/ghidra/12.2/libexec"
JAVA = "/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home"


def timed(command: list[str], environment: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "fixture.bin"
        shutil.copyfile(command[-1], copy)
        command = [*command[:-1], str(copy)]
        start = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
        seconds = time.monotonic() - start
        return {"seconds": round(seconds, 1), "exit": process.returncode, "stdout_bytes": len(process.stdout),
                "error": process.stdout[:300] if process.returncode or '"error"' in process.stdout[:200] else None}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("procedure")
    parser.add_argument("out", type=Path)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--rea-timeout-ms", type=int, default=3_600_000)
    parser.add_argument("--rea-maxmem", default="16G")
    arguments = parser.parse_args()
    base = {name: os.environ[name] for name in ("HOME", "PATH", "TMPDIR", "USER") if name in os.environ}
    rampage = ROOT / "target/release/rampage"
    rea = ROOT / "target/bench/rea/src/scripts/rea.mjs"
    rea_environment = {**base, "GHIDRA_INSTALL_DIR": GHIDRA, "JAVA_HOME": JAVA, "REA_ANALYSIS_PROVIDER": "ghidra",
                       "REA_GHIDRA_STARTUP_TIMEOUT_MS": str(arguments.rea_timeout_ms),
                       "GHIDRA_HEADLESS_MAXMEM": arguments.rea_maxmem}
    results: dict = {"file_sha256": hashlib.sha256(arguments.file.read_bytes()).hexdigest(),
                     "file_bytes": arguments.file.stat().st_size, "rampage": [], "rea": [],
                     "rampage_command": "rampage --json function list FILE",
                     "rea_command": f"rea decompile FILE --procedure {arguments.procedure} --provider ghidra",
                     "rea_ghidra_startup_timeout_ms": arguments.rea_timeout_ms,
                     "rea_ghidra_headless_maxmem": arguments.rea_maxmem}
    for _ in range(arguments.repeat):
        results["rampage"].append(timed([str(rampage), "--json", "function", "list", str(arguments.file)], base))
        rea_command = ["node", str(rea), "decompile", "--procedure", arguments.procedure, "--provider", "ghidra",
                       "--format", "json", str(arguments.file)]
        results["rea"].append(timed(rea_command, rea_environment))
        print(json.dumps(results, indent=1), flush=True)
    arguments.out.write_text(json.dumps(results, indent=1) + "\n")


if __name__ == "__main__":
    main()
