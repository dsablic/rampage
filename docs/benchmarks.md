# Accuracy benchmarks

rampage's analysis is measured against Ghidra as a reference. Ghidra's output is a reference, not ground truth:
a matching function start does not establish a matching CFG, types or decompilation, and either tool can be
wrong. The point is to catch regressions and large gaps in rampage's own analysis.

## Function discovery vs Ghidra

`tools/benchmark.sh` runs Ghidra headless to list function starts, builds a reference in rampage's format
(matching the image SHA-256 and architecture), and runs `rampage compare` against it.

```
tools/benchmark.sh target/debug/rampage "$(brew --prefix ghidra)/libexec" \
  tests/fixtures/bin/hello-x64.elf x86_64  tests/fixtures/bin/hello-arm64.elf aarch64
```

`recall` is matched/reference starts; `precision` is matched/rampage starts. Extra starts are now counted against
precision, including thunks excluded from the reference. Empty denominators are reported as `null`/`N/A`, not
zero. The reference records the installed Ghidra version. These policies must match before comparisons across
versions or corpora are interpreted.

### Results (Ghidra 12.1.4, fixtures in `tests/fixtures/bin`)

| binary            | arch     | ghidra | rampage | matched | recall |
|-------------------|----------|-------:|--------:|--------:|-------:|
| hello-x64.elf     | x86_64   |     41 |      41 |      41 | 100.0% |
| hello-x64-dyn.elf | x86_64   |      6 |       6 |       5 |  83.3% |
| hello-x64.exe     | x86_64   |    497 |     525 |     497 | 100.0% |
| hello-arm64.elf   | aarch64  |      6 |       8 |       5 |  83.3% |
| hello-arm.elf     | arm      |      4 |      10 |       4 | 100.0% |
| hello-thumb.elf   | arm      |     44 |      44 |      43 |  97.7% |
| hello-mips.elf    | mips     |      3 |       5 |       3 | 100.0% |
| hello-ppc.elf     | powerpc  |     42 |      42 |      42 | 100.0% |
| hello-riscv64.elf | riscv64  |      8 |       8 |       8 | 100.0% |

On the larger PE sample rampage matches every Ghidra function. The 83–98% cases are small fixtures where a
single miss is a large percentage; the known gap is a startup/stub entry (such as the ARM `0x10100` veneer) that
Ghidra treats as a function and rampage does not yet discover. These are tracked for discovery work separately
from the embedded decompiler's integration accuracy.

## Basic blocks, CFG edges and call edges vs Ghidra

`tools/cfg-benchmark.py` compares, on the functions both tools find (same entry address), each function's
basic-block starts, its intra-function successor edges and its call edges. Ghidra is the reference here, not ground
truth: "precision" is the share of rampage's items Ghidra also has, "recall" the share of Ghidra's items rampage
also has, and the analysis below shows disagreements where rampage is right and Ghidra is not.

```
tools/cfg-benchmark.py target/release/rampage "$(brew --prefix ghidra)/libexec" \
  tests/fixtures/bin/hello-x64.elf tests/fixtures/bin/hello-x64.exe ... --out /tmp/cfg-report
```

- Ghidra side: headless auto-analysis, then `tools/ghidra_cfg_export.java` writes each non-thunk function's
  `BasicBlockModel` blocks, successors that stay inside the function body, and call references.
- rampage side: `rampage export-cfg FILE` (hidden subcommand) writes the same `function_graph` blocks and edges and
  `xrefs --from` references the MCP tools return, without the 60k-character tool-output bound.
- Normalisation: a rampage jump to another function's entry counts as a call, because Ghidra records tail calls as
  call references. Ghidra `COMPUTED_CALL*` targets (every computed-call reference kind) count only when rampage
  found the same call; the rest are listed in their own column. These targets come from memory reads, and some are
  garbage (see below).
- Totals pool items per function, keyed by (function entry, address), so a block or edge that two functions share
  counts in each of them.
- `block J` is the Jaccard index of all block starts. `chain J` and `chain edge` merge straight-line chains, where a
  block is its predecessor's only successor, on both sides before comparing. This removes Ghidra's extra splits at
  labelled instructions.
- `--out DIR` writes each fixture's full report, named after the fixture plus a digest of its path. It lists, per
  function, blocks, edges and calls found by only one tool. The ten worst functions per fixture also go to stderr.
  `--ghidra-cache DIR` reuses Ghidra exports, keyed by image SHA-256, Ghidra version and a digest of the export
  script. When the export is missing or truncated, the script exits with the end of Ghidra's output and logs.
- `python3 -m unittest tools.test_cfg_benchmark` tests the comparison and caching logic without Ghidra.

### Results

Ghidra 12.1.4 (headless, default analysers, OpenJDK 21.0.12.1); rampage 0.1.0 at `207c45c`; macOS 27.0.1 arm64.
Ghidra's analysis takes 4–23 s per fixture, about 2.5 min for all 18 fixtures, so all of them are covered. A second
run at `af40350` (regenerated signature databases), with Ghidra's exports cached, gave the same numbers.

| binary | funcs G/R/both | same blocks | block J | chain J | edge P / R | chain edge P / R | call P / R | callgraph P / R | G-only computed calls |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| hello-x64.elf | 41/41/41 | 41/41 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-x64-dyn.elf | 6/7/6 | 6/6 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-x64.exe | 497/525/497 | 461/497 | 95.6% | 96.2% | 99.9% / 94.8% | 99.9% / 95.2% | 100.0% / 94.3% | 100.0% / 93.7% | 1 |
| hello-x64.macho | 2/3/2 | 2/2 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-arm64.elf | 6/9/6 | 6/6 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-arm64.macho | 2/3/2 | 2/2 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-arm.elf | 4/11/4 | 4/4 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-thumb.elf | 44/44/43 | 36/43 | 96.3% | 97.9% | 95.9% / 94.9% | 97.8% / 99.6% | 100.0% / 97.9% | 100.0% / 97.7% | 2 |
| hello-mips.elf | 3/5/3 | 2/3 | 60.0% | 75.0% | N/A / 0.0% | N/A / 0.0% | 0.0% / N/A | 0.0% / N/A | 2 |
| hello-mipsel.elf | 3/5/3 | 2/3 | 60.0% | 75.0% | N/A / 0.0% | N/A / 0.0% | 0.0% / N/A | 0.0% / N/A | 2 |
| hello-ppc.elf | 42/42/42 | 42/42 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 95.9% | 100.0% / 95.5% | 3 |
| hello-ppc64le.elf | 7/7/4 | 4/4 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | N/A / N/A | N/A / N/A | 0 |
| hello-riscv64.elf | 8/9/8 | 5/8 | 57.9% | 100.0% | 0.0% / 0.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 3 |
| eval-ref-x86_64.elf | 176/176/176 | 169/176 | 91.1% | 91.2% | 100.0% / 90.2% | 99.9% / 90.2% | 100.0% / 92.2% | 100.0% / 93.9% | 1 |
| eval-ref-aarch64.elf | 194/195/194 | 189/194 | 99.8% | 100.0% | 98.5% / 98.4% | 100.0% / 100.0% | 99.8% / 100.0% | 99.7% / 100.0% | 2 |
| musl-static-x86_64.elf | 67/67/67 | 65/67 | 90.9% | 90.8% | 99.8% / 89.6% | 99.7% / 89.4% | 100.0% / 97.8% | 100.0% / 97.7% | 0 |
| musl-static-aarch64.elf | 82/83/82 | 79/82 | 99.7% | 100.0% | 98.1% / 97.9% | 100.0% / 100.0% | 99.5% / 100.0% | 99.1% / 100.0% | 1 |
| hello-go-x64.elf | 1358/1806/1357 | 1322/1357 | 94.9% | 94.9% | 95.8% / 94.2% | 95.6% / 94.3% | 99.6% / 93.9% | 99.4% / 97.1% | 57 |

`N/A` means an empty denominator: the shared functions are single-block, or have no calls. The MIPS, RISC-V and
small Mach-O/ARM fixtures share only 2–8 functions, so their percentages move a lot with a single decision.

### Main disagreement classes

These come from inspecting the per-function reports (`--out`) and the disassembly at the listed addresses.

- **Unresolved x86-64 jump tables (rampage misses blocks).** These cause almost all of the missing blocks, edges
  and calls outside Go. Every Ghidra-only block in hello-x64.exe (239 blocks in 34 functions), eval-ref-x86_64
  (328) and musl-static-x86_64 (82) is in a function with a switch dispatch that Ghidra resolved and rampage left
  as an indirect jump. In Go, such functions hold 934 of the 1245 Ghidra-only blocks. The calls inside those
  unreached cases are what lowers call recall. Forms seen: absolute `jmp [rax*8+0x1001a68]` (eval-ref-x86_64
  `0x100e148`); MSVC/MinGW-style relative `lea rcx,[table]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax`
  (hello-x64.exe `0x1400170f4`).
- **AArch64 jump tables (resolved).** rampage resolves every AArch64 switch in these fixtures under its
  bounded-switch rule. The index needs an unsigned bound from a `cmp` directly followed by `b.hi`/`b.hs`, no branch
  may join between that comparison and the `br`, and the table must be read-only data. That covers the compact
  `adr; ldrb/ldrh; add x, x, w, lsl #2; br` tables (musl-static-aarch64 `0x10149dc`, eval-ref-aarch64 `0x10184a0`)
  and `ldrsw` with an unrelated `movk` scheduled in between (eval-ref-aarch64 `0x102386c`). Each case gets a
  `switch` edge from the dispatch block. The remaining Ghidra-only blocks (3 in musl-static-aarch64, 6 in
  eval-ref-aarch64) are all the `br` itself: Ghidra starts a block at its `switchD` label, so its case edges leave
  from there, while rampage's leave from the block that ends in the `br`. Chain Jaccard and chain edges, which
  merge that split, agree completely.
- **No noreturn knowledge (rampage adds edges).** rampage falls through after every call. Ghidra ends the block at
  calls to non-returning functions. In Go, 896 of rampage's 1321 extra edges are fall-throughs out of a block that
  Ghidra ends with no successor, mostly after `runtime.throw`/`runtime.panic*` (for example `0x409e20`,
  `0x4337e0`). In hello-x64.exe, rampage adds edges after `exit`, `abort` and the MinGW error reporter `0x140001d20`
  (`0x1400013f7`, `0x1400013fc`, `0x140001cdd`). This is a precision loss in the CFG, and it also lets bodies run
  into the following code.
- **Get-PC idioms and `bl next`.** rampage turns a call whose target is the next instruction into plain flow. On
  MIPS that check compares against the delay slot, so `__start`'s `bal 0x203fc` (target after the delay slot) stays
  a call. That creates a function `sub_203fc` in the middle of `__start` (hello-mips/mipsel `0x203f4`); Ghidra
  treats it as a branch. The same rule drops real calls whose callee happens to be next:
  `bl 0x20804` (`_Exit`) at hello-thumb `0x20800` and `bl 0x20790` (`_start_c`) at hello-ppc `0x2078c`. These are
  the PPC and Thumb call-recall misses.
- **Tail jumps to import thunks.** In hello-x64.exe, `jmp 0x140028d50` (the `fflush` IAT thunk) at `0x140001447`
  is folded into the caller as an intra-function block, because only one function jumps there. Ghidra calls it a
  thunk call. The same happens at `0x140001790` to `0x140028e10`.
- **Ghidra's label splits (not a CFG difference).** `BasicBlockModel` starts a block at every labelled
  instruction. On RISC-V the `.Lpcrel_hi*` local symbols split straight-line code, so raw block Jaccard is 57.9% and
  chain Jaccard is 100%.
- **Ghidra-side disagreements where rampage is right.**
  - Go ABI0 wrappers (`runtime.schedinit` at `0x480660` jumps to `0x448860`): Ghidra has no function at the
    pclntab-listed target, so it folds the whole target body into the wrapper. These 19 functions account for
    311 Ghidra-only blocks.
  - musl-static-aarch64 `0x1012690`: `adr x3, 0x1012694; ...; br x3` is a tail call that rampage resolves and
    Ghidra does not.
  - Ghidra `COMPUTED_CALL` targets read through unrelocated memory, for example `0x10102464c457f`, which is the ELF
    header bytes, on hello-arm64 and eval-ref-aarch64.
  - On Thumb, Ghidra leaves the reachable `udf` trap block out after `bgt` (hello-thumb `0x204fa`, `0x207aa`);
    rampage keeps it.

### Analysis follow-ups found by this benchmark

1. Resolve x86-64 jump tables, both the absolute `[reg*8+table]` and the relative `movsxd`+`add` forms. Evidence:
   eval-ref-x86_64 `0x100e148`, hello-x64.exe `0x1400170f4`.
2. Extend AArch64 switch recovery to the bounds it does not yet prove: the inverse form, where `b.ls`/`b.lo` jumps
   to the dispatch and the fall-through is the default, and a `cmp` scheduled away from its conditional branch.
   None of these fixtures needs either.
3. Add noreturn analysis: imports (`exit`, `abort`), Go `runtime.throw`/`panic*`, and functions whose every path
   ends in a noreturn call. Evidence: about 900 extra Go edges; hello-x64.exe `0x1400013f7`.
4. `rampage-arch` `Kind::flow` (`crates/rampage-arch/src/flow.rs`) compares a call target with the address right
   after the instruction. With delay slots it should compare with the address after the slot; MIPS `bal` creates a
   bogus `sub_203fc`. A call whose target is a known function or symbol should stay a call: hello-thumb `0x20800`
   and hello-ppc `0x2078c` lose their call edges.
5. A tail jump to an import thunk reached by a single caller is absorbed into that caller (hello-x64.exe
   `0x140001447`). Treat `jmp [IAT]` stubs as functions.
6. hello-arm.elf lists `sub_2036c`, whose first word (`7cfffeff`) does not decode, as a function with no blocks.
   `function_graph` on it then fails with "no function contains 0x2036c". `export-cfg`
   reports it with empty blocks.
7. Disassembly text only: RISC-V compressed branches print the relative offset (`c.beqz a1, 0x22` at hello-riscv64
   `0x10015d0`) rather than the target `0x10015f2`; the decoded flow is correct.

## Decompilation

rampage uses Ghidra's decompiler engine, but identical engines do not guarantee identical results. Memory mappings,
processor context, compiler specifications, relocation handling, symbols/types and analysis options all affect output.
Differential decompilation must compare equivalent inputs and settings rather than assuming agreement.

Remaining metrics include success/warning coverage, inferred signatures, typed calls, recovered strings and switch
targets, and time/memory use. Function-start recall alone does not establish decompiler accuracy or tool parity.

`tools/decompile-benchmark.sh RAMPAGE GHIDRA IMAGE FUNCTION` runs a bounded single-function reference probe and
reports image identity, engine/compiler selection, normalized text equality and warning lines in emitted C.
It explicitly reports that mappings/types/options are not yet matched; equality is diagnostic rather than a
semantic score. On `hello-x64-dyn.elf`/`main`, Ghidra 12.1.4 produced 77 bytes and rampage produced 79 bytes, both
without emitted warning lines. The differing display names/signatures require matched-setting comparison before
an accuracy conclusion is drawn.

The versioned integration corpus runs with
`python3 tools/decompiler_corpus.py target/debug/rampage --manifest tests/data/decompiler-corpus.json --isolated`.
Its four controlled cases passed 15 selected assertions (x64/ARM64 greeting calls, BE8 instructions and Windows
x64 arguments). That pass is bounded integration coverage, not a general decompilation accuracy percentage.
