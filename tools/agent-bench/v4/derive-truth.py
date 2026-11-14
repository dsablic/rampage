"""Derive every suite-v4 answer from sources, symbols and deterministic harness runs, then compare with the task
manifests. Neither benchmarked server is used: the tools are LLVM's (llvm-nm, llvm-objcopy), this script's own
CMSIS-SVD reader, image.py's checksum and HEX/S-record code, and host programs it compiles from the owned sources.

Usage: python3 -I tools/agent-bench/v4/derive-truth.py [--only TASK] [--update] [--json OUT]

--update rewrites each derived task's fixture digest and [answer] block in its manifest, and each export task's
expected image (tests/fixtures/bench-v4/truth/) and its digest in neutral-v4.toml, from what was derived; use it
after rebuilding a fixture, never to make a run pass. The address checks below still apply.

Harness runs: the Cortex-M sources are compiled for the host with -DHOST, where every register access goes
through host_read/host_write (src/device.h). The harness records the accesses in program order and answers reads
(clock ready, serial port ready, overrun pending, made-up chip IDs, a fuse counter above the image version), so
"which registers does this function access, in which order, with which values" comes from running the source.

The regression tasks are suite v3's manifests, copied unchanged; their truths are v3's (derive-truth.py there).
This script checks that the copies are byte-identical.

Exits non-zero when a derived truth disagrees with a manifest, an address the question names differs from the
derived one, a stripped fixture's loaded bytes differ from its twin's, or a digest differs from its manifest.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FIX = ROOT / "tests/fixtures/bench-v4"
TASKS = ROOT / "crates/rampage-eval/tasks/v4"
V3_TASKS = ROOT / "crates/rampage-eval/tasks/v3"
NEUTRAL = ROOT / "crates/rampage-eval/tasks/h2h/neutral-v4.toml"
LLVM = Path("/opt/homebrew/opt/llvm/bin")
SVD = FIX / "companions/benchm4.svd"
M0_TRUTH = ROOT / "tests/fixtures/data/eval-truth-embedded-m0.json"


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v2 = load("v2_truth", HERE.parent / "v2/derive-truth.py")
image = load("v4_image", HERE / "image.py")
run, symbols, sha256 = v2.run, v2.symbols, v2.sha256

REGRESSION = ["semantics-wide-x86-elf", "switch-pic-x86-so", "callconv-arguments-x86-pe",
              "type-indirect-offsets-arm64-elf"]


class Truth:
    """A derived answer, plus the addresses the task's question must name."""

    def __init__(self, answer: dict[str, Any], mentions: list[int] | None = None) -> None:
        self.answer = answer
        self.mentions = mentions or []


def compile_and_run(sources: list[Path], arguments: list[str], flags: tuple[str, ...] = (),
                    extra: str | None = None) -> str:
    """Compile owned sources (and an optional harness) for the host, run in an empty directory; standard output."""
    with tempfile.TemporaryDirectory() as directory:
        program = Path(directory) / "program"
        work = Path(directory) / "work"
        work.mkdir()
        files = [str(source) for source in sources]
        if extra is not None:
            harness = Path(directory) / "harness.c"
            harness.write_text(extra)
            files.append(str(harness))
        run("clang", "-O1", "-w", "-I", FIX / "src", *flags, "-o", program, *files)
        return subprocess.run([str(program), *arguments], capture_output=True, text=True, cwd=work, check=True,
                              timeout=60).stdout


def twin(name: str) -> dict[str, int]:
    return symbols(FIX / "twins" / name)


# ---------------------------------------------------------------------------------------------------------------
# Emulation: host runs of src/emulate.c, at two optimization levels.

EMULATION = {
    "emulate-mix-x64-elf": ("emulate-x64.elf", "mix_rounds", ["0x00C0FFEE", "1000"]),
    "emulate-libc-arm64-elf": ("emulate-arm64-dyn.elf", "token_digest", ["bench-v4-token"]),
    "emulate-control-thumb-elf": ("emulate-thumb.elf", "settle", ["40000", "500"]),
    "emulate-wide-mips-elf": ("emulate-mips.elf", "collatz_weight", ["63728127"]),
}


def emulation(task: str) -> Truth:
    binary, function, arguments = EMULATION[task]
    source = FIX / "src/emulate.c"
    result = int(compile_and_run([source], [function, *arguments], ("-DHOST_MAIN",)), 16)
    assert result == int(compile_and_run([source], [function, *arguments], ("-DHOST_MAIN", "-O0")), 16)
    assert result < 1 << 63, "the manifest format holds signed 64-bit integers"
    return Truth({"result": result}, [twin(binary)[function] & ~1])


# ---------------------------------------------------------------------------------------------------------------
# String decoding: what each call site prints, from a host build of the same source.

STRINGS = {
    "strings-rolling-x64-elf": ("strdec-x64.elf", "report_calibration_error", "1", 0),
    "strings-alphabet-arm64-elf": ("strdec-arm64.elf", "announce_service", "2", 0),
}


def strings(task: str) -> Truth:
    binary, function, variant, call = STRINGS[task]
    arguments = ["x"] * call
    text = compile_and_run([FIX / "src/strdec.c"], arguments, (f"-DVARIANT={variant}",)).rstrip("\n")
    assert "\n" not in text and text.isprintable(), text
    return Truth({"text": text}, [twin(binary)[function]])


# ---------------------------------------------------------------------------------------------------------------
# CMSIS-SVD: this script's own reader (peripherals with derivedFrom, registers, fields).


def svd_map() -> tuple[dict[int, str], dict[str, list[tuple[str, int, int]]]]:
    """Register address -> PERIPHERAL.REGISTER, and PERIPHERAL.REGISTER -> [(field, offset, width)]."""
    root = ElementTree.parse(SVD).getroot()
    peripherals = {p.findtext("name"): p for p in root.iter("peripheral")}
    names: dict[int, str] = {}
    fields: dict[str, list[tuple[str, int, int]]] = {}
    for name, peripheral in peripherals.items():
        source = peripherals[peripheral.get("derivedFrom")] if peripheral.get("derivedFrom") else peripheral
        base = int(peripheral.findtext("baseAddress"), 0)
        for register in source.iter("register"):
            qualified = f"{name}.{register.findtext('name')}"
            names[base + int(register.findtext("addressOffset"), 0)] = qualified
            fields[qualified] = [(field.findtext("name"), int(field.findtext("bitOffset")),
                                  int(field.findtext("bitWidth"))) for field in register.iter("field")]
    return names, fields


HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint32_t host_image_version = 7, host_pairing_token = 0x5EED1E55u;
uint32_t host_read(uint32_t address) {
  uint32_t value = 0;
  switch (address) {
  case 0x40000008u: value = 1; break;                     /* CLKCTRL.STAT: READY */
  case 0x40002008u: value = 0xB; break;                   /* UART0.STATUS: TXE, RXNE, OVR; BUSY clear */
  case 0x4000200Cu: value = 0x41; break;                  /* UART0.DATA */
  case 0x1FFF7000u: value = 0x00470031u; break;           /* UID.UID0..2: made-up chip IDs */
  case 0x1FFF7004u: value = 0x33385104u; break;
  case 0x1FFF7008u: value = 0x20313438u; break;
  case 0x40009010u: value = 9; break;                     /* OTP.MINVER above the image's version 7 */
  }
  printf("R %#x\n", address);
  return value;
}
void host_write(uint32_t address, uint32_t value) { printf("W %#x %#x\n", address, value); }
@DECLARATIONS@
int main(int argc, char **argv) {
  (void)argc;
  @CALLS@
  return 2;
}
"""


def accesses(source: str, function: str, declaration: str, call: str) -> list[tuple[str, int, int | None]]:
    """Run one firmware function on the host; its register accesses in program order."""
    calls = f'if (!strcmp(argv[1], "{function}")) {{ {call}; return 0; }}'
    program = HARNESS.replace("@DECLARATIONS@", declaration).replace("@CALLS@", calls)
    output = compile_and_run([FIX / "src" / source], [function], ("-DHOST",), program)
    rows = []
    for line in output.splitlines():
        parts = line.split()
        rows.append((parts[0], int(parts[1], 16), int(parts[2], 16) if len(parts) > 2 else None))
    return rows


PERIPH_FUNCTIONS = {
    "clock_init": ("void clock_init(void);", "clock_init()"),
    "gpio_setup": ("void gpio_setup(void);", "gpio_setup()"),
    "uart_init": ("void uart_init(uint32_t);", "uart_init(115200)"),
    "uart_putc": ("void uart_putc(uint32_t);", "uart_putc(65)"),
    "uart_getc": ("uint32_t uart_getc(void);", "uart_getc()"),
    "uart_flush": ("void uart_flush(void);", "uart_flush()"),
    "uart_overrun": ("uint32_t uart_overrun(void);", "uart_overrun()"),
    "timer_setup": ("void timer_setup(uint32_t);", "timer_setup(16000)"),
    "timer_elapsed": ("uint32_t timer_elapsed(uint32_t);", "timer_elapsed(16000)"),
    "watchdog_start": ("void watchdog_start(uint32_t);", "watchdog_start(4000)"),
    "watchdog_kick": ("void watchdog_kick(void);", "watchdog_kick()"),
    "led_set": ("void led_set(uint32_t, uint32_t);", "led_set(1, 1); led_set(1, 0)"),
    "button_pressed": ("uint32_t button_pressed(void);", "button_pressed()"),
}


def periph(function: str) -> list[tuple[str, int, int | None]]:
    declaration, call = PERIPH_FUNCTIONS[function]
    return accesses("periph.c", function, declaration, call)


def svd_registers_written() -> Truth:
    names, _ = svd_map()
    writes = [names[address] for kind, address, _ in periph("timer_setup") if kind == "W"]
    return Truth({"registers": writes}, [twin("periph-cm4.elf")["timer_setup"]])


def svd_fields_set() -> Truth:
    names, fields = svd_map()
    writes = [(address, value) for kind, address, value in periph("uart_init") if kind == "W"]
    register = "UART0.CTRL"
    last = [value for address, value in writes if names[address] == register][-1]
    assert len([1 for address, _ in writes if names[address] == register]) > 1
    set_fields = [name for name, offset, width in fields[register] if (last >> offset) & ((1 << width) - 1)]
    return Truth({"fields": sorted(set_fields)}, [twin("periph-cm4.elf")["uart_init"]])


def svd_status_readers() -> Truth:
    names, _ = svd_map()
    table = twin("periph-cm4.elf")
    readers = [table[function] for function in PERIPH_FUNCTIONS
               if any(kind == "R" and names.get(address) == "UART0.STATUS" for kind, address, _ in periph(function))]
    # Leaves only: none of the listed functions calls another, so a direct read is the same as a read anywhere.
    source = (FIX / "src/periph.c").read_text()
    for function in PERIPH_FUNCTIONS:
        body = re.split(r"\nNOINLINE |\n#", source.split(f" {function}(", 1)[1], maxsplit=1)[0]
        assert not any(f"{other}(" in body for other in PERIPH_FUNCTIONS if other != function), function
    return Truth({"values": sorted(readers)}, [])


# ---------------------------------------------------------------------------------------------------------------
# Patching: image.py's checksums on the patched flat image, cross-checked against a host run of boot.c's own
# routines.

CRC_HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
uint16_t crc16_ccitt(const uint8_t *, uint32_t);
uint32_t crc32_ieee(const uint8_t *, uint32_t);
uint32_t host_read(uint32_t address) { (void)address; return 0; }
void host_write(uint32_t address, uint32_t value) { (void)address; (void)value; }
int main(int argc, char **argv) {
  static uint8_t image[0x1400];
  FILE *file = fopen(argv[1], "rb");
  if (argc != 2 || !file || fread(image, 1, sizeof image, file) != sizeof image) return 2;
  printf("%#x %#x\n", crc16_ccitt(image + 0x800, 0x40), crc32_ieee(image + 0x800, 0x13FC - 0x800));
  return 0;
}
"""


def boot_image() -> bytearray:
    data = bytearray((FIX / "bin/boot-cm4.bin").read_bytes())
    assert len(data) == 0x1400, len(data)
    stored = (int.from_bytes(data[0x840:0x842], "little"), int.from_bytes(data[0x13FC:0x1400], "little"))
    assert boot_checksums(data) == stored, "the fixture's own checksums do not hold"
    return data


def boot_checksums(data: bytes) -> tuple[int, int]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "image.bin"
        path.write_bytes(bytes(data))
        host = compile_and_run([FIX / "src/boot.c"], [str(path)], ("-DHOST",), CRC_HARNESS).split()
    ours = (image.crc16_ccitt_false(bytes(data[0x800:0x840])), image.crc32_ieee(bytes(data[0x800:0x13FC])))
    assert tuple(int(value, 16) for value in host) == ours, (host, ours)
    return ours


def patched(changes: dict[int, bytes]) -> bytearray:
    data = boot_image()
    for address, replacement in changes.items():
        data[address : address + len(replacement)] = replacement
    image.seal(data)
    assert boot_checksums(data) == (int.from_bytes(data[0x840:0x842], "little"),
                                    int.from_bytes(data[0x13FC:0x1400], "little"))
    return data


def patch_values() -> Truth:
    original = boot_image()
    assert image.decode_ihex((FIX / "bin/boot-cm4.hex").read_text()) == dict(enumerate(original)), "HEX differs"
    assert int.from_bytes(original[0x808:0x80C], "little") == 115200
    data = patched({0x808: (57600).to_bytes(4, "little")})
    changed = []
    for address, width in ((0x840, 2), (0x13FC, 4)):
        if data[address : address + width] != original[address : address + width]:
            changed.append([address, int.from_bytes(data[address : address + width], "little")])
    return Truth({"fields": changed}, [0x808])


EXPORTS = {
    "patch-export-srec-cm4-srec": {0x80C: b"\x03"},
    "patch-export-bin-cm4-raw": {0x810: b"BENCH-UNIT-0042"},
}


def export_image(task: str) -> bytearray:
    original = boot_image()
    if task == "patch-export-srec-cm4-srec":
        assert original[0x80C] == 0x01
        records = image.decode_srec((FIX / "bin/boot-cm4.srec").read_text())
        assert records == dict(enumerate(original)), "S-records and flat image differ"
    else:
        assert original[0x810:0x820] == b"BENCH-UNIT-0001\0"
    return patched(EXPORTS[task])


def export_truth(task: str) -> Truth:
    export_image(task)
    return Truth({"written": True}, list(EXPORTS[task]))


# ---------------------------------------------------------------------------------------------------------------
# Locks: twin symbols and source constants, with the decision's inputs and refusal from a host run.

GUARD = {
    "enforce_pairing": ("void enforce_pairing(void);", "host_pairing_token ^= 1; enforce_pairing()"),
    "enforce_version": ("void enforce_version(void);", "enforce_version()"),
}


def refusal(rows: list[tuple[str, int, int | None]]) -> str:
    if ("W", 0xE000ED0C, 0x05FA0004) in rows:
        return "reset"
    # On the target both refusal paths end in HALT() (an endless wfi loop) unless they requested a reset first.
    return "halt"


def lock_binding() -> Truth:
    names, _ = svd_map()
    declaration, call = GUARD["enforce_pairing"]
    rows = accesses("guard.c", "enforce_pairing", declaration, call)
    ids = sorted(address for kind, address, _ in rows if kind == "R" and names.get(address, "").startswith("UID."))
    table = twin("guard-cm4.elf")
    return Truth({"decision_function": table["enforce_pairing"], "id_registers": ids,
                  "reference": table["PAIR_TOKEN"], "refusal": refusal(rows)}, [])


def lock_rollback() -> Truth:
    names, _ = svd_map()
    declaration, call = GUARD["enforce_version"]
    rows = accesses("guard.c", "enforce_version", declaration, call)
    counters = [address for kind, address, _ in rows if kind == "R" and names.get(address) == "OTP.MINVER"]
    assert len(counters) == 1
    table = twin("guard-cm4.elf")
    return Truth({"decision_function": table["enforce_version"], "counter_register": counters[0],
                  "image_version": table["IMAGE_HEADER"] + 4, "refusal": refusal(rows)}, [])


# ---------------------------------------------------------------------------------------------------------------
# Library identification: the held-out fixture's committed libid truth (from its symbolized build).

LIBID = {
    "libid-names-m0-elf": ["strlen", "strcmp", "strchr", "strncpy", "qsort"],
    "libid-names-m0-raw": ["memset", "memmove", "malloc", "strtol", "__udivsi3"],
}
# The answer field for a library name the question describes rather than spells (__udivsi3 is also __aeabi_uidiv).
ANSWER_FIELD = {"__udivsi3": "unsigned_divide"}


def libid(task: str) -> Truth:
    truth = json.loads(M0_TRUTH.read_text())
    by_name: dict[str, list[int]] = {}
    for address, name in truth.items():
        by_name.setdefault(name, []).append(int(address, 16))
    answer = {}
    for name in LIBID[task]:
        assert len(by_name[name]) == 1, name
        answer[ANSWER_FIELD.get(name, name)] = by_name[name][0]
    return Truth(answer, [])


DERIVATIONS = {
    **{task: (lambda task=task: emulation(task)) for task in EMULATION},
    **{task: (lambda task=task: strings(task)) for task in STRINGS},
    "svd-registers-written-cm4-raw": svd_registers_written,
    "svd-fields-set-cm4-raw": svd_fields_set,
    "svd-status-readers-cm4-raw": svd_status_readers,
    "patch-values-cm4-hex": patch_values,
    **{task: (lambda task=task: export_truth(task)) for task in EXPORTS},
    "lock-binding-cm4-raw": lock_binding,
    "lock-rollback-cm4-raw": lock_rollback,
    **{task: (lambda task=task: libid(task)) for task in LIBID},
}


# ---------------------------------------------------------------------------------------------------------------
# Fixture checks: stripping changes no loaded byte, and each flat image is its twin's bytes.

ELF_PAIRS = ["emulate-x64.elf", "emulate-arm64-dyn.elf", "emulate-thumb.elf", "emulate-mips.elf", "strdec-x64.elf",
             "strdec-arm64.elf"]
RAW_IMAGES = {
    "periph-cm4.bin": ("periph-cm4.elf", ["--gap-fill", "0xff", "-j", ".text", "-j", ".rodata"], []),
    "guard-cm4.bin": ("guard-cm4.elf", ["--gap-fill", "0xff", "-j", ".text", "-j", ".rodata", "-j", ".imghdr", "-j", ".pair"], []),
    "boot-cm4.bin": ("boot-cm4.elf", ["--gap-fill", "0xff", "-j", ".text", "-j", ".rodata", "-j", ".cfg", "-j", ".cfg_crc", "-j",
                                      ".app", "-j", ".app_crc"], [(0x840, 2), (0x13FC, 4)]),
}


def fixture_problems() -> list[str]:
    problems = []
    for name in ELF_PAIRS:
        if not v2.same_image(FIX / "bin" / name, FIX / "twins" / name):
            problems.append(f"{name}: stripped loaded image differs from its twin")
    for name, (elf, options, sealed) in RAW_IMAGES.items():
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "image.bin"
            run(LLVM / "llvm-objcopy", "-O", "binary", *options, FIX / "twins" / elf, out)
            expected, actual = bytearray(out.read_bytes()), bytearray((FIX / "bin" / name).read_bytes())
        for address, width in sealed:
            expected[address : address + width] = actual[address : address + width]
        if expected != actual:
            problems.append(f"{name}: differs from its twin's bytes")
    return problems


# ---------------------------------------------------------------------------------------------------------------
# Manifests.


def manifest(task: str) -> dict[str, Any]:
    return tomllib.loads((TASKS / f"{task}.toml").read_text())


def expected(task: str) -> dict[str, Any]:
    answer = manifest(task)["answer"]
    if answer["kind"] == "exact":
        return answer["fields"]
    return {answer["field"]: answer["values"]}


def agrees(task: str, derived: dict[str, Any]) -> bool:
    answer = manifest(task)["answer"]
    want = expected(task)
    if answer["kind"] == "exact":
        return derived == want
    key = answer["field"]
    return list(derived) == [key] and sorted(map(json.dumps, derived[key])) == sorted(map(json.dumps, want[key]))


def toml_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value)


def update(task: str, derived: dict[str, Any]) -> None:
    """Rewrite the manifest's fixture digests and answer block from the derived truth."""
    path = TASKS / f"{task}.toml"
    text = path.read_text()
    fixture = manifest(task)["fixture"]
    text = text.replace(f'sha256 = "{fixture["sha256"]}"', f'sha256 = "{sha256(ROOT / fixture["path"])}"', 1)
    for companion in fixture.get("companions", []):
        text = text.replace(f'sha256 = "{companion["sha256"]}"', f'sha256 = "{sha256(ROOT / companion["path"])}"', 1)
    head, answer = text.split("[answer]\n", 1)
    kind = re.search(r'^kind = "(\w+)"$', answer, re.MULTILINE).group(1)
    lines = [f'kind = "{kind}"']
    if "hex_integers = true" in answer:
        lines.append("hex_integers = true")
    if kind == "exact":
        lines.append("[answer.fields]")
        lines += [f"{key} = {toml_value(value)}" for key, value in derived.items()]
    else:
        (key, values), = derived.items()
        lines += [f'field = "{key}"', f"values = {toml_value(values)}"]
    path.write_text(head + "[answer]\n" + "\n".join(lines) + "\n")


def export_problems(update_files: bool) -> list[str]:
    """Each export task's expected image file and its digest in neutral-v4.toml."""
    problems = []
    neutral_text = NEUTRAL.read_text()
    neutral = tomllib.loads(neutral_text)
    for task in EXPORTS:
        spec = neutral["tasks"][task]["output"]
        data = bytes(export_image(task))
        path = ROOT / spec["expected"]
        if update_files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            neutral_text = neutral_text.replace(spec["expected_sha256"], v2.hashlib.sha256(data).hexdigest(), 1)
        elif not path.is_file() or path.read_bytes() != data:
            problems.append(f"{task}: {spec['expected']} is not the derived image")
        elif sha256(path) != spec["expected_sha256"]:
            problems.append(f"{task}: expected_sha256 differs from {spec['expected']}")
        if spec["base"] != 0:
            problems.append(f"{task}: the image is mapped at 0")
    if update_files:
        NEUTRAL.write_text(neutral_text)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--only")
    arguments = parser.parse_args()
    problems = fixture_problems()
    for task in REGRESSION:
        if (TASKS / f"{task}.toml").read_bytes() != (V3_TASKS / f"{task}.toml").read_bytes():
            problems.append(f"{task}: differs from suite v3's manifest")
    problems += export_problems(arguments.update and not arguments.only)
    derived: dict[str, Any] = {}
    for task, derive in DERIVATIONS.items():
        if arguments.only and task != arguments.only:
            continue
        truth = derive()
        derived[task] = truth.answer
        if arguments.update:
            update(task, truth.answer)
        entry = manifest(task)
        for address in truth.mentions:
            if not re.search(rf"\b0x{address:x}\b", entry["question"], re.IGNORECASE):
                problems.append(f"{task}: the question does not name {address:#x}")
        if sha256(ROOT / entry["fixture"]["path"]) != entry["fixture"]["sha256"]:
            problems.append(f"{task}: {entry['fixture']['path']} differs from the manifest digest")
        for companion in entry["fixture"].get("companions", []):
            if sha256(ROOT / companion["path"]) != companion["sha256"]:
                problems.append(f"{task}: {companion['path']} differs from the manifest digest")
        if not agrees(task, truth.answer):
            problems.append(f"{task}: derived {truth.answer} but the manifest expects {expected(task)}")
    print(json.dumps(derived, indent=1))
    if arguments.json:
        arguments.json.write_text(json.dumps(derived, indent=1) + "\n")
    for line in problems:
        print("PROBLEM:", line, file=sys.stderr)
    print(f"{len(derived)} tasks derived, {len(problems)} problems", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
