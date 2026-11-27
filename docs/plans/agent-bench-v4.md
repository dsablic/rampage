# Head-to-head suite v4: design (built, not run)

Suite v4 of the rampage-vs-REA agent benchmark covers what shipped after the 1.0.0 feature set that
[suite v3](../benchmarks/agent-h2h-v3-2026-11-14.md) measured: function emulation, run-time string decoding,
CMSIS-SVD peripheral maps, firmware checksum repair and image export, Cortex-M library identification and lock
explanation. Four v3 tasks come along unchanged so drift stays visible. Nothing here has been run through a model;
this document is the design for the fairness review that precedes a run.

## Where things are

| What | Where |
| --- | --- |
| Task manifests (question, fixture, truth, answer contract) | `crates/rampage-eval/tasks/v4/` |
| Tool-neutral prompts, categories, scoring rules, output files | `crates/rampage-eval/tasks/h2h/neutral-v4.toml` |
| Owned sources, build script, fixtures, twins, SVD, expected images | `tests/fixtures/bench-v4/` |
| Truth derivation (sources, symbols, host harness runs) | `tools/agent-bench/v4/derive-truth.py` |
| Checksums and HEX/S-record codec used by the build and the truth | `tools/agent-bench/v4/image.py` |
| Reachability through rampage's MCP tools (no model) | `tools/agent-bench/v4/validate-rampage.py`, `mcp_client.py` |
| Hand-written correct and incorrect replies per task | `tools/agent-bench/v4/checker-cases.json` |
| Report views, declared before any run | `tools/agent-bench/v4/report-views.py` |
| Harness: `--suite v4`, file outputs checked after a run | `crates/rampage-eval/src/agent_bench_run.rs`, `agent_bench_artifact.rs` |
| Tests | `crates/rampage-eval/tests/agent_bench_v4.rs` |

The runner (`tools/agent-bench/claude-runner.py`) is unchanged.

## Tasks (20)

Each row: what the task measures, the feature it exercises on rampage's side, and the truth source. Addresses are
those the question names.

| Task | Category | Measures | rampage feature | Truth |
| --- | --- | --- | --- | --- |
| `emulate-mix-x64-elf` | emulation | the result of 1,000 rounds of xorshift + S-box + rotate (x86-64) | `evaluate_function` | host run of `emulate.c` at -O1 and -O0 |
| `emulate-libc-arm64-elf` | emulation | FNV-style digest of a string, through `strlen`/`memset`/`memcpy` imports (AArch64, dynamic) | `evaluate_function` libc stand-ins, buffer arguments | host run |
| `emulate-control-thumb-elf` | emulation | 500 steps of an integer control loop with `udiv` and remainders (Cortex-M4 ELF at 0x0) | `evaluate_function` (Thumb) | host run |
| `emulate-wide-mips-elf` | emulation | 949 Collatz steps in 64-bit arithmetic on 32-bit big-endian MIPS | `evaluate_function` (o32, register pairs) | host run |
| `strings-rolling-x64-elf` | strings | the text a function prints after a rolling-key XOR decode | `string_decoding` `evaluate: true` | host run of `strdec.c` |
| `strings-alphabet-arm64-elf` | strings | the same with a position-shifted 64-entry alphabet decoder (AArch64) | `evaluate_function` (`string_decoding` finds no candidate; see gaps) | host run |
| `svd-registers-written-cm4-raw` | peripherals | registers a function writes, in order, as `PERIPHERAL.REGISTER` (`TIMER1` is `derivedFrom` `TIMER0`) | `import_svd`, decompiled MMIO names | host harness run, own SVD reader |
| `svd-fields-set-cm4-raw` | peripherals | bit fields set by the last write to a control register | `import_svd` field comments | host harness run, own SVD reader |
| `svd-status-readers-cm4-raw` | peripherals | every function that reads a status register (a writer is a distractor) | `xrefs` with `access`, `peripheral_access` | host harness run of every function, twin symbols |
| `patch-values-cm4-hex` | patching | new values of every integrity field after a config change (Intel HEX input; a CRC-16 inside a CRC-32's range) | `integrity_checks` | `image.py` checksums, cross-checked against a host run of the firmware's own routines |
| `patch-export-srec-cm4-srec` | patching | patch a byte, repair the checksums, write S-records covering the same addresses | `patch_bytes`, `integrity_checks fix`, `export_image` | expected image file (`truth/`), checked byte for byte |
| `patch-export-bin-cm4-raw` | patching | the same for a flat binary (a 15-character label changed) | same | same |
| `lock-binding-cm4-raw` | locks | explain a chip-ID binding: decision function, ID registers, compared stored value, refusal kind | `lock_mechanisms` with the SVD | host harness run (UID reads, AIRCR write), twin symbols |
| `lock-rollback-cm4-raw` | locks | explain an anti-rollback check: decision function, fuse counter register, image version address, refusal kind | `lock_mechanisms` | host harness run, twin symbols |
| `libid-names-m0-elf` | libraries | entry addresses of strlen, strcmp, strchr, strncpy, qsort in stripped Cortex-M0 firmware (ELF) | `identify_functions` embedded set | committed held-out libid truth |
| `libid-names-m0-raw` | libraries | memset, memmove, malloc, strtol and the 32-bit unsigned division helper in the same firmware's flash image | `identify_functions` on a Raw project | same |
| `semantics-wide-x86-elf` | regression | v3 task, unchanged (64-bit result on i686) | (v3 miss class; now `evaluate_function`) | v3 |
| `switch-pic-x86-so` | regression | v3 task, unchanged | jump tables | v3 |
| `callconv-arguments-x86-pe` | regression | v3 task, unchanged | calling conventions | v3 |
| `type-indirect-offsets-arm64-elf` | regression | v3 task, unchanged | type propagation | v3 |

The regression subset takes one task from each of four v3 categories that ran on committed fixtures in seconds
(no Go, SQLite or MSVC builds): semantics (the category whose misses motivated `evaluate_function`), switch tables,
calling conventions and typing. The manifests are byte-identical copies (a test checks this) and keep their v3
wording and scoring; only the neutral suite's category label is `regression`.

### Fixtures

All fixtures are owned and built from committed sources by `tests/fixtures/bench-v4/build.sh` with zig 0.17 and
LLVM; a rebuild reproduces every digest. The Cortex-M sources target a made-up `BENCHM4` device described by
`companions/benchm4.svd` (invented names and addresses, generic CMSIS conventions; Apache-2.0). There is no vendor
or product name, real device firmware or key anywhere: the pairing token and salts are invented constants that
match no unit.

The library tasks reuse the committed held-out fixture `tests/fixtures/firmware/embedded-libs-m0.{elf,bin}`: a
FreeRTOS (MIT) application linked with newlib and libgcc from Arm GNU Toolchain 14.3.rel1, which the embedded
signature set was not built from (CONTRIBUTING accepts newlib/libgcc in firmware fixtures). Its truth is the
committed `tests/fixtures/data/eval-truth-embedded-m0.json`, taken from the symbolized build. The prompts name
neither the kernel nor the toolchain.

The functions the library tasks ask for were chosen by a rule fixed before any tool was run on them: C library
functions the fixture's own `main.c` calls by name, split between the two tasks, plus the compiler's division
helper. Validation then showed which of them rampage's signatures name (below); the choice was not revised.

### Truth

`derive-truth.py` derives every v4 answer without either server: emulation and string answers from host builds of
the owned sources (two optimization levels, so no answer depends on undefined behaviour); peripheral and lock
answers from a host harness that compiles the firmware sources with `-DHOST`, records every register access in
program order and answers reads (`src/device.h`); register and field names from the script's own CMSIS-SVD
reader; checksums from `image.py`, cross-checked against a host run of the firmware's own CRC routines; addresses
from the unstripped twins' symbols; library addresses from the held-out truth. It also checks that every stripped
fixture's loaded bytes equal its twin's, that the HEX and S-record files decode to the flat image, that the
regression manifests equal v3's, and that every digest matches. `--update` rewrites answers, digests and the
expected export images after a rebuild.

### Scoring

As in v3: the final reply must be one JSON object with exactly the requested fields; integers may be `0x`
strings where the task allows; sets are compared without order and with partial credit (Jaccard), ordered lists in
order. Strict is the headline; the lenient variant forgives only an extra `"status":"ok"` field.

New in v4, two tasks ask for a file. `{output}` in the question becomes the quoted path beside the fixture; after
the run the harness decodes the file with readers independent of both servers (`agent_bench_artifact.rs`: Intel
HEX, S-records with every record checksum verified, or a flat binary at the stated base) and requires exactly the
expected addresses with exactly the expected bytes. The run is correct only when the reply (`{"written": true}`)
and the file both pass; a failing file is `wrong_artifact`, and the lenient variant never forgives it. The harness
keeps a private copy of the file and the verdict (`artifact.json`) in the run directory, so `--rescore` reuses the
verdict after the working directory is gone. The expected images are checked against digests in the neutral
suite before any run starts.

## Validation done (no model)

- **Checkers.** `checker-cases.json` holds 2–4 hand-written correct replies and 2–5 near misses for each of the 20
  tasks (one hex digit off, signed instead of unsigned, a missing or extra item, the wrong order, a wrong refusal
  kind, a wrong-case register name, a stale checksum, a decimal string, an extra `"status"` field).
  `suite_v4_checkers_accept_correct_and_reject_incorrect_replies` requires every correct reply to match and every
  near miss to fail. The file checks are tested against an S-record file written by an encoder other than the
  checker's (rampage's export of the correctly patched image), the unpatched input, Intel HEX in place of
  S-records, a dropped record, a changed digit without its checksum, a missing terminator, and flat images one
  byte short and one byte long.
- **Truths.** `derive-truth.py`: 16 derived, 0 problems (the 4 regression truths are v3's).
- **Reachability through rampage.** `validate-rampage.py` calls rampage's MCP server directly (release build of
  this branch, analysis cache off, the files copied under the harness's names) with one scripted route per task
  and compares what it reads with the truth: **10 of 16 reached** as built; the six gaps are listed next. After the
  fixes below (made after the suite found the gaps, on Unreleased): **14 of 16**, the two signature-recall gaps
  remaining. The routes read a
  few values the way a reader of the tool output would (a register name in decompiled code, a literal address in
  a disassembly); those reads are scripted by pattern and named in each route.

### Gaps validation found in rampage (decide before the run)

These are rampage limitations, found on fixtures designed without reference to them. Every task still has a route
through rampage (reading code, plus a CRC-16 by hand for the patching tasks), so all six stay in the suite; the
views report them apart (`known_rampage_gaps`).

1. **`evaluate_function` cannot run code mapped at address 0** (`emulate-control-thumb-elf`): it stops with
   `unmapped_fetch` at 0x144. The same function linked at 0x8000 runs and returns the truth. Firmware linked at
   0x0 is common, so this is a real gap, not a fixture artifact. **Fixed after the suite found it** (Unreleased): page 0 of a
   fixed-address image linked there (Raw, or an ELF executable) is mapped; the route now reaches the truth.
2. **`integrity_checks` misses the CRC-16/CCITT-FALSE at 0x840** (all three patching tasks). It finds the CRC-32
   at 0x13FC (polynomial formed by `movw`/`movt`), but not the 16-bit field right after the 64-byte configuration
   block, whose routine the compiler turned into a table lookup. `fix: true` then writes a CRC-32 computed over the
   stale CRC-16 (`0x7cf33297` instead of `0xc2980fa1`), so the exported image fails the boot code. And
   `evaluate_function` refuses Raw projects, so an agent cannot run the image's own CRC-16 routine either. With the
   correct CRC-16 patched in by hand, the rest of the route (`integrity_checks fix`, `export_image` to S-records)
   produces exactly the expected image; that export is the checker's test file. **Fixed after the suite found it** (Unreleased):
   `integrity_checks` now finds the nested CRC-16 (table address formed by `movw`/`movt`, range and stored value
   passed as immediates) and fixes it before the CRC-32; all three patching routes reach the truth. `evaluate_function`
   now also accepts Raw projects (Unreleased), so the image's CRC-16 routine can be run directly.
3. **Embedded signatures name 4 of the 10 asked library functions** (`libid-names-m0-elf`: strlen, strcmp,
   strchr, not strncpy or qsort; `libid-names-m0-raw`: `__udivsi3`, not memset, memmove, malloc or strtol). That
   matches the published 31% recall on this held-out fixture; the rest must be recognised from their code.

Two further observations change no truth but matter to how an agent reads rampage's output:

- `string_decoding` finds no candidate for the alphabet decoder (table-driven; its limitations say so). The route
  that works is reading the call (blob address and length) and running the decoder with `evaluate_function`. **Fixed
  after the suite found it** (Unreleased): table-lookup loops passed encoded-looking data are candidates, and
  `string_decoding` with `evaluate: true` decodes all three alphabet blobs.
- In rampage's decompiled `enforce_pairing`, the `SCB.AIRCR` reset request before the wait loop is gone (only the
  `WaitForInterrupt` loop remains), and both lock functions show the flash reads at 0xC80 and 0xC04 folded to
  constants. `lock_mechanisms` reports the reset correctly and the disassembly shows both addresses, so the truth
  is reachable, but an agent that trusts the decompiled C alone would answer "halt" and miss the addresses. **Fixed
  after the suite found it** (Unreleased): on Cortex-M Raw images flash words read through a formed address no
  longer fold and the peripheral and system ranges are volatile, so `enforce_pairing` shows
  `ppb_e000ed0c = 0x5fa0004` before the wait loop and both functions read `code_c80` / `code_c04`.

**Decision taken:** gaps 1 and 2, `evaluate_function` on Raw projects and both observations were fixed before any
run (one commit each, each with tests on images other than these fixtures where one exists), so the report must
disclose that these fixes were made after the fixtures existed. Gap 3 (signature recall) is unchanged.

**Owner decision (as first written):** run as built (a measurement of 1.2.0 + Unreleased as they are), or fix gaps 1
and 2 first. If
they are fixed first, the report must disclose that the fixes were made after these fixtures existed (as v3
disclosed its suite timing), and the fixes should be validated on other images too, not tuned to these.

## Fairness

v3's fairness review is the precedent: truth independent of both servers, tool-neutral prompts, strict scoring by a
checker defined before any run, no task that only rampage's documentation makes answerable.

- **Prompts.** No prompt names a tool, a server or a route; a test rejects rampage's and REA's tool names and
  concepts, plus "emulat", "signature" and "decompile". Every question states what an analyst would know anyway
  (architecture, load address, calling convention, argument widths). The system prompt is v1's.
- **Answer-shape line (from 2026-11-27).** The closing instruction now says an answer has no `"status"` field, with
  `{"result":42}` against `{"status":"ok","result":42}` as the example: agents had copied the shape of the
  `{"status":"unknown",…}` fallback around right values on four releases. It applies to every suite and server.
  Passes before 1.20.0's follow-ups ran without it; compare strict scores across that line with care (lenient
  scoring already accepted the wrapped value).
- **REA's route exists for every task.** REA was run with Rizin 0.9.1 installed in v3, and v4 keeps that setup.
  Spot checks without a model: Rizin disassembles the raw Thumb images (`e asm.bits=16`), reads the S-record and
  SVD files, and its shell escape (`!python3 …`, `!cat …`) works through `execute_rizin_command`. Per category:
  - emulation and strings: Ghidra's pseudocode (the same decompiler rampage embeds), then Rizin's ESIL emulator,
    a script through the shell escape, or hand arithmetic (v3's failure mode, now on longer loops);
  - peripherals and locks: the SVD read as text through Rizin, Thumb code through Rizin (REA's Ghidra raw loader
    offers ARMv7 without Thumb, v2's finding);
  - patching: checksums through Rizin's hash commands with `io.cache` writes, or a script; a flat binary through
    `wtf`; S-records only through the shell escape;
  - libraries: Ghidra's function ID has no Cortex-M newlib database in the default install, so recognition from
    code, the same as rampage's six unnamed functions.
- **General command runner (confirm).** `patch-export-srec-cm4-srec` is the one task whose only REA route found is
  Rizin's shell escape (to encode S-records). That is part of REA's advertised catalog and v3 counted it; the view
  `without_general_runner` scores the suite without that task, so the call can go either way after the run.
- **The suite's own files stay out of reach, and a run that reaches them fails.** The truth export images
  (`tests/fixtures/bench-v4/truth/*.bin`), the unstripped twins, the sources and `derive-truth.py` live in the
  repository, and both servers can open any path (rampage's `path`, REA's Rizin shell escape). The runner already
  stages only the task's input file and companions, copied into a private `0700` directory under the system temp
  directory, outside the repository, and names only those paths in the prompt; it does not sandbox the servers.
  So every scored run's transcript (tool calls, tool results and the agent's text; not the client's setup lines)
  is screened: a mention of `bench-v4/`, `/twins/`, `truth/`, `derive-truth` or the repository root scores the run
  wrong with failure `contaminated` and the line it was found on, whatever it answered, on rescores too. The
  export check refuses a symbolic link in place of the written file, and `--rescore` checks the saved copy of the
  file again against the current truth.
- **No rampage-only rows in the head-to-head.** No v4 task lacks an REA route, so all 20 are scored head-to-head.
- **`debug_snapshot raw: true` is left out of v4.** A flash dump needs a live target: the harness would have to
  start an emulated board (QEMU with a GDB stub) per run, which it has no lifecycle for, and REA's GDB sessions are
  Linux-only (`start_gdb_session`: "Persistent GDB sessions are available only on Linux"), so on this macOS host REA
  lacks the capability entirely. The feature is already covered by the live QEMU test. If wanted later, it belongs
  in a rampage-only capability row, reported apart from the head-to-head: the harness starts
  `qemu-system-arm -S -gdb tcp::PORT` with an owned image, the agent dumps the flash and answers one question about
  it, and the row is scored like v1's capability probes, never in the head-to-head totals.
- **Locks are explanation only.** Both lock prompts say "explain that check; nothing needs to be changed" and ask
  for what is checked, where the decision is made and what refusal does, in a fixed neutral vocabulary (`reset`,
  `halt`, `error_return`, `flag`, defined in the prompt). No task asks to bypass, patch around or extract a key;
  the patching tasks change a configuration value and a label in an owned image and repair its integrity checks,
  which the fixture's comments state are not locks.
- **Calls the owner should confirm:**
  1. counting Rizin's shell escape as an REA capability (above), with the `without_general_runner` view;
  2. running with the six known gaps as they are, or fixing gaps 1 and 2 first with the disclosure above;
  3. the library tasks' a-priori function choice, which favours neither server by construction but gives rampage
     names for only 4 of 10;
  4. reusing the held-out `embedded-libs-m0` fixture (its recall is already published) instead of building a new
     one, which needs the Arm GNU Toolchain download;
  5. `emulate-wide-mips-elf`'s argument: 63728127 fits in 32 bits, so rampage's `evaluate_function` needs
     `bits: 64` to place it in a0:a1 (its schema documents this; a plain integer silently gives a wrong result);
     the question states the argument is 64-bit, so this is kept as a fair test of reading the tool's contract.

## Cost estimate

From v3's measured per-run costs on `claude-sonnet-5-5` (rampage $0.066 and REA $0.117 per run on average; per
category for the analogues) and v2's firmware rows (about $0.10 per run for both servers), with headroom for the
multi-step firmware tasks, where REA is expected to script through Rizin:

| Category (tasks) | rampage $/run | REA $/run | Basis |
| --- | --: | --: | --- |
| emulation (4) | 0.06 | 0.08 | v3 semantics 0.060 / 0.058, REA adds a script or ESIL |
| strings (2) | 0.07 | 0.10 | v3 semantics, longer for REA |
| peripherals (3) | 0.10 | 0.15 | v2 firmware 0.105 / 0.103, plus reading the SVD |
| patching (3) | 0.15 | 0.25 | several patch/check/export steps; REA scripts checksums |
| locks (2) | 0.10 | 0.15 | v2 firmware |
| libraries (2) | 0.08 | 0.15 | v3 symbols 0.038 / 0.145, rampage's signatures cover only some |
| regression (4) | 0.060 | 0.070 | v3 measured on these four tasks |

| Pass | Runs | Estimated cost |
| --- | --: | --: |
| Sonnet 5.5 headline: 20 tasks × 2 servers × 3 repetitions | 120 | about $13 (rampage $5.2, REA $7.8); cap at $20 |
| Haiku 5.5 routine pass: 20 × 2 × 1 | 40 | about $0.35 ($0.10/$0.50 per MTok, 1/20 of Sonnet's rates, with 1.5× more turns assumed) |
| Haiku 5.5 at 3 repetitions | 120 | about $1 |

Wall time: no fixture needs a long Ghidra import (the largest is 72 KB), so at v3's per-run medians (11 s rampage,
32 s REA) a Sonnet pass takes about 1.5 hours with headroom. Run the Haiku pass first to shake out harness issues
(the file outputs are new), then the Sonnet pass with `--cost-cap-usd 20`.

## Run recipe

```sh
python3 -I tools/agent-bench/v4/derive-truth.py           # 16 derived, 0 problems
python3 -I tools/agent-bench/v4/validate-rampage.py --rampage target/release/rampage   # gaps as listed
cargo build --release -p rampage-cli -p rampage-worker && cargo build --release -p rampage-eval
target/release/rampage-eval agent-bench --suite v4 --servers rampage,rea --repeat 1 --model claude-haiku-5-5 \
  --cost-cap-usd 2 --label haiku-v4-<date>
target/release/rampage-eval agent-bench --suite v4 --servers rampage,rea --repeat 3 --model claude-sonnet-5-5 \
  --cost-cap-usd 20 --label full-v4-<date> \
  --report-json docs/benchmarks/agent-h2h-v4-<date>.json --report-md docs/benchmarks/agent-h2h-v4-<date>.md
python3 -I tools/agent-bench/v4/report-views.py REPORT.json VIEWS.json docs/benchmarks/agent-h2h-v3-2026-11-14.json
```

## Not validated

- No agent run of any kind (by design: no model usage was spent).
- REA's routes were spot-checked, not scripted end to end. Through REA's own MCP server (commit `970969c`, Ghidra
  12.2): `execute_rizin_command` prints the SVD file; `open_binary` imports `strdec-x64.elf` in 0.6 s and
  `procedure_pseudo_code` decompiles the Thumb ELF's 0x144; Ghidra names none of four checked library functions in
  `embedded-libs-m0.elf` (`FUN_08007ea0` for strlen, and likewise strncpy, qsort and `__udivsi3`), so REA's agent
  must recognise all ten from code. Through Rizin directly (as `execute_rizin_command` runs it): the raw Thumb
  images disassemble with `e asm.bits=16`, the S-record file reads as text, and the shell escape runs Python. REA's
  raw-binary import of the HEX/S-record inputs and full patch/export routes were not exercised.
- The regression truths were not re-derived here; they are v3's, and the manifests are byte-identical.
- The harness's file check ran in unit tests and on a real export, not inside a full `agent-bench` run.
