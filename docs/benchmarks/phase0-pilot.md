# Phase 0 pilot and raw-window acceptance

Part of the [accuracy benchmarks](../benchmarks.md).

## Raw-window workflow acceptance

| Workload | Before | Reviewed raw-window slice |
| --- | --- | --- |
| Local raw-firmware code range, no bundled input | Native-header refusal | One MCP query: 218 bytes, 84 rows, no unconsumed bytes |
| Owned Thumb assembly and literal pool | No raw-file MCP route | Compiled source fixture: three instructions, exact literal and source offsets checked |

The firmware query corroborated decoder parameters through static instructions. Its base/mode remain analyst
assertions; row counts are not instruction-accuracy or execution measurements. No commercial bytes, addresses
or payloads are included here. Broader parity metrics belong to the Phase 0 scorecard, not this acceptance check.

## Parity scorecard pilot

Local working-tree baseline based on `6fcdae2`; generated artifacts and the evaluator digest/dirty state are
recorded in `target/parity/phase0-20261017-matrix/scorecard.json`, not bundled binaries. These are pilot measurements,
not completed Phase 0 acceptance or a comparison with an IDA/Ghidra agent.

| Metric | Pilot result |
| --- | --- |
| AArch64 ELF `-O2` function starts | 39 correct, 0 missed, 0 spurious |
| Thumb ELF `-O2` function starts | 4 correct, 0 missed, 0 spurious |
| MIPS32 big-endian ELF `-O2` function starts | 4 correct, 0 missed, 0 spurious |
| AArch64 parameter counts | 38 correct, 1 wrong; precision/recall 0.9744 |
| AArch64 parameter type classes | 42 correct, 26 wrong, 1 missed; precision 0.6176, recall 0.6087 |
| AArch64 eligible void/value returns | 34 correct; precision/recall 1.0 on that eligible set |
| Agent task definitions | 17 analysis questions and 3 capability probes; all 10 fixture digests matched |
| Fixed-model MCP tasks and usage | Not run; no success, call or token numbers inferred |
| Type-selected AArch64 decompiler health | 39 exact-entry returns, 0 API errors or diagnostic warnings |
| Owned Thumb graph reference | Ghidra 12.1.4: 4 common functions, 12 shared raw CFG edges (13/14 totals) |
| Thumb chain-normalized CFG / calls | 13/13 edges and 3/3 source-instruction call pairs match |

The pilot emits combined JSON; an initial `--suite parity` invocation failed with unsupported `--suite`.
Selected failed runs retain evidence: local clang lacked the requested linker; one run used a bad Zig Thumb CPU
spelling, since corrected; the original strip path rejected MIPS section type `0x7000002a`, which mapped-byte
refusal checks handle. The nine-profile matrix records three available, three unavailable and three failed selections;
missing GCC/strip/linker support and a PE linker argument remain visible rather than counting as coverage.
Cross-program library ID, broad graph/health coverage and model comparisons remain unmeasured in this pilot.
The health sample's 39 calls totalled about 275 ms on one local run; initialization/cache state is not controlled,
so this is not a warm/cold or per-function performance baseline. Per-entry timings remain in the local report.

### Broader source-built baseline

Working-tree measurements based on `950bac2`; receipts retain executable/source hashes and actual tool versions.
The Lua 5.4.8 MIT archive is pinned to the upstream published checksum; no downloaded sources or binaries are
committed. Full reports are local `target/parity/lua-20261017-01`, `coverage-20261017-02` and
`coverage-languages-20261017-03` outputs. No target programs were executed.
The expanded combined receipt is `target/parity/expanded-20261017/scorecard.json`: 19 metric slices across
the verified profiles and Lua, with both manifest digests and the Lua graph binding retained.

| Workload / metric | Measured result |
| --- | --- |
| System-Clang x64 ELF function starts | 39 correct, no misses or extra starts |
| System-Clang x64 parameter counts / classes | 36 correct, 3 wrong / 43 correct, 23 wrong, 3 missed |
| Zig/embedded-Clang x64 ELF | Same counts on this fixture; a separate profile, not GCC coverage |
| Owned Go x64 ELF function starts | 1815 correct, no misses, 1 extra; runtime metadata retained |
| Owned compressed Go arm64 Mach-O starts | 1898 DWARF starts found, no misses, 44 extra candidates |
| Owned x64 PE starts | 4 DWARF starts found, no misses or extra candidates |
| Lua AArch64 ELF function starts | 892 correct, no misses, 6 extra; precision 0.9933 |
| Lua matched-twin naming, including static runtime | 849 correct, 43 missed, no wrong/spurious names; recall 0.9518 |
| Lua/Ghidra 12.1.4 function coverage | 890 common, 8 rampage-only, none Ghidra-only |
| Lua raw CFG edges | 16947 shared; totals 17233 / 17207 (rampage / Ghidra) |
| Lua chain-normalized CFG edges | 17183 shared; totals 17228 / 17183 |
| Lua call-site pairs / call-graph edges | 4373 / 2890 shared; one rampage-only item in each metric |

Matched-twin naming is best-case same-build evaluation. Graph agreement is limited to common functions and
does not establish correctness. Explicit contiguous DWARF truth checks all retained ranges in both PE
and compressed Go Mach-O twins; unsupported range-list functions and unavailable names remain omitted.
The 14-profile matrix has 8 scored, 5 unavailable and 1 failed profile. Native C++/exceptions, Rust and the
basic Mach-O build lack supported truth; Linux C++ lacks a local target runtime; genuine GCC is absent.
Extra candidates are relative to the retained truth, not independently confirmed false function starts.
