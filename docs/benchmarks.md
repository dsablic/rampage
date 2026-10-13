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
| hello-arm.elf     | arm      |      4 |       8 |       4 | 100.0% |
| hello-thumb.elf   | arm      |     44 |      43 |      43 |  97.7% |
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
run at `af40350` (regenerated signature databases), with Ghidra's exports cached, gave the same numbers. The x86-64
rows (hello-x64.exe, eval-ref-x86_64, musl-static-x86_64, hello-go-x64) were re-measured with x86 switch tables
resolved, from the same cached exports; the other x86-64 rows did not change. The hello-x64.exe, ARM, Thumb, MIPS,
PPC and RISC-V rows were re-measured the same way after the get-PC, import-thunk and undecodable-start fixes.
Adding noreturn analysis changed only the hello-x64.exe and hello-go-x64 rows (re-measured the same way). Every
row below was last re-measured at `7c03e5c`, from the same cached exports, after switch resolution started
forgetting facts at joins ahead of the comparison and stopped accepting 16-bit `movsxd` and non-contiguous masks;
no row changed. They were re-measured again at `41e1224`, from the same cached exports, after the noreturn review
fixes (conditional calls and returns, resumable traps, incremental inference, case-sensitive names, more get-PC
idioms); no row changed. Re-measured again, from the same cached exports, after the address a load reads stopped
counting as a code pointer: only the hello-arm.elf (10 to 8 rampage functions) and hello-thumb.elf (44 to 43) rows
changed. Inferring noreturn through mutual tail calls then changed no row.

| binary | funcs G/R/both | same blocks | block J | chain J | edge P / R | chain edge P / R | call P / R | callgraph P / R | G-only computed calls |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| hello-x64.elf | 41/41/41 | 41/41 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-x64-dyn.elf | 6/7/6 | 6/6 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-x64.exe | 497/537/497 | 463/497 | 99.2% | 99.8% | 98.0% / 97.3% | 100.0% / 99.7% | 100.0% / 99.8% | 100.0% / 100.0% | 1 |
| hello-x64.macho | 2/3/2 | 2/2 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-arm64.elf | 6/9/6 | 6/6 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-arm64.macho | 2/3/2 | 2/2 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-arm.elf | 4/8/4 | 4/4 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-thumb.elf | 44/43/43 | 36/43 | 96.3% | 97.9% | 95.9% / 94.9% | 97.8% / 99.6% | 100.0% / 100.0% | 100.0% / 100.0% | 2 |
| hello-mips.elf | 3/3/3 | 2/3 | 80.0% | 100.0% | 50.0% / 33.3% | 100.0% / 100.0% | N/A / N/A | N/A / N/A | 2 |
| hello-mipsel.elf | 3/3/3 | 2/3 | 80.0% | 100.0% | 50.0% / 33.3% | 100.0% / 100.0% | N/A / N/A | N/A / N/A | 2 |
| hello-ppc.elf | 42/42/42 | 42/42 | 100.0% | 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 3 |
| hello-ppc64le.elf | 7/7/4 | 4/4 | 100.0% | 100.0% | N/A / N/A | N/A / N/A | N/A / N/A | N/A / N/A | 0 |
| hello-riscv64.elf | 8/9/8 | 5/8 | 57.9% | 100.0% | 0.0% / 0.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% | 3 |
| eval-ref-x86_64.elf | 176/176/176 | 171/176 | 99.8% | 99.9% | 99.0% / 98.8% | 100.0% / 99.8% | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| eval-ref-aarch64.elf | 194/195/194 | 189/194 | 99.8% | 100.0% | 98.5% / 98.4% | 100.0% / 100.0% | 99.8% / 100.0% | 99.7% / 100.0% | 2 |
| musl-static-x86_64.elf | 67/67/67 | 66/67 | 99.6% | 99.6% | 100.0% / 99.3% | 100.0% / 99.3% | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| musl-static-aarch64.elf | 82/83/82 | 79/82 | 99.7% | 100.0% | 98.1% / 97.9% | 100.0% / 100.0% | 99.5% / 100.0% | 99.1% / 100.0% | 1 |
| hello-go-x64.elf | 1358/1806/1357 | 1321/1357 | 98.6% | 98.8% | 99.3% / 96.9% | 100.0% / 97.7% | 99.7% / 97.9% | 99.5% / 98.5% | 57 |

`N/A` means an empty denominator: the shared functions are single-block, or have no calls. The MIPS, RISC-V and
small Mach-O/ARM fixtures share only 2–8 functions, so their percentages move a lot with a single decision.

### Main disagreement classes

These come from inspecting the per-function reports (`--out`) and the disassembly at the listed addresses.

- **x86-64 jump tables (mostly resolved).** rampage resolves an x86 switch under the same bounded-switch rule as
  AArch64. The index needs an unsigned bound, from a `cmp` directly followed by `ja`/`jae` or from an
  `and r, mask`, covering the whole register (a 32-bit write or `mov e, e` zero-extends it). No branch may join
  the straight-line run that proves the bound, the zero extension and the table base, and the table must be
  read-only data. This covers absolute
  `jmp [rax*8+0x1001a68]` (eval-ref-x86_64 `0x100e148`) and relative
  `lea rcx,[table]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax` (hello-x64.exe `0x1400170f4`, bounded by
  `and eax, 3`). Ghidra-only blocks fell from 239 to 44 in hello-x64.exe, 328 to 8 in eval-ref-x86_64, 82 to 4 in
  musl-static-x86_64 and 1245 to 330 in Go. Most of what remains is the jump itself: as on AArch64, Ghidra starts a
  block at its `switchD` label, which also accounts for the lower raw edge precision. The switches still unresolved
  take their index or table register from another block, which the straight-line tracking does not follow:
  `printf_core` compares `r12d` and jumps through `r13` (eval-ref-x86_64 `0x1008e60`), and hello-x64.exe
  `0x140001aca` uses a table base loaded into `r15` before its loop.
- **AArch64 jump tables (resolved).** rampage resolves every AArch64 switch in these fixtures under its
  bounded-switch rule. The index needs an unsigned bound from a `cmp` directly followed by `b.hi`/`b.hs`, no branch
  may join between that comparison and the `br`, and the table must be read-only data. That covers the compact
  `adr; ldrb/ldrh; add x, x, w, lsl #2; br` tables (musl-static-aarch64 `0x10149dc`, eval-ref-aarch64 `0x10184a0`)
  and `ldrsw` with an unrelated `movk` scheduled in between (eval-ref-aarch64 `0x102386c`). Each case gets a
  `switch` edge from the dispatch block. The remaining Ghidra-only blocks (3 in musl-static-aarch64, 6 in
  eval-ref-aarch64) are all the `br` itself: Ghidra starts a block at its `switchD` label, so its case edges leave
  from there, while rampage's leave from the block that ends in the `br`. Chain Jaccard and chain edges, which
  merge that split, agree completely.
- **Noreturn calls (resolved; Ghidra now adds edges).** rampage ends a block at a call to a function that never
  returns: one in its curated list (`exit`, `abort`, `__stack_chk_fail`, `_CxxThrowException`, Rust
  `core::panicking::*`, Go `runtime.throw`/`runtime.gopanic`/`runtime.panic*`, ...), called directly, through a
  PLT/IAT stub or through an import slot, or one inferred because every path through it ends in such a call or a
  trap. Before, rampage fell through after every call. Go's rampage-only edges drop from 1536 to 206 (edge
  precision 95.3% to 99.3%), and hello-x64.exe loses its 7 fall-throughs after `exit`, `abort` and the MinGW error
  reporter `0x140001d20` (`0x1400013f7`, `0x1400013fc`, `0x140001cdd`). Go edge recall falls from 98.0% to 96.9%:
  330 edges Ghidra keeps after calls that never return, such as `runtime.gopanic`, `runtime.panicshift`,
  `runtime.panicunsafeslicelen` and the dead code after `runtime.fatalthrow` in `runtime.fatal` (`0x444054`).
  Ghidra lists most of these callees as non-returning itself but does not end every such block. Go's
  `runtime.mcall` and `runtime.morestack*` end every path in a trap or a noreturn call yet resume their caller
  through a saved context, so they are never inferred noreturn. A conditional call (`blne abort`, Thumb `it ne;
  bl`) never ends its block, and a conditional return or register jump (`bxeq lr`, `popne {r7, pc}`, PowerPC
  `beqlr`) counts as a way out, so neither makes its function look noreturn. Only traps that cannot resume (`ud2`,
  `udf`, AArch64 `brk #1`/`#0x3e8`, RISC-V `unimp`, SPARC `illtrap`, PowerPC `trap`) count as evidence; debugger
  and semihosting traps (`bkpt`, `hlt`, other `brk`s, MIPS `break`, RISC-V `ebreak`) fall through. Inference
  re-explores only the callers of newly inferred functions, so hello-go-arm64 discovery takes 48 ms instead of
  150 ms (hello-go-x64: 41 instead of 70 ms) with the same CFGs. `function_graph` and `export-cfg` mark each such
  call `listed` or `inferred`. Functions that only tail-call each other are inferred together, by a greatest
  fixpoint over the tail-call graph, when some path among them ends in such a call or trap; a tail-call cycle with
  no such path is an infinite loop, which Ghidra calls non-returning but rampage leaves unknown for lack of
  evidence.
- **Get-PC idioms (resolved).** A call whose target is the instruction after it (after the delay slot on MIPS and
  SPARC) reads the PC only when the code there takes the return address: `bal 1f; nop; 1: ... addu $gp, $gp, $ra`
  (hello-mips/mipsel `__start`), `bl 1f; 1: mflr r30`, `bl 1f; 1: mov r0, lr` (ARM, Thumb, AArch64),
  `call 1f; 1: pop ebx` or `mov ebx, [esp]`, a MIPS delay slot or `$ra`-based load. rampage treats those as plain flow
  and every other call to the next instruction as a call, so `bl _Exit` (hello-thumb `0x20800`) and `bl _start_c`
  (hello-ppc `0x2078c`) keep their call edges. Ghidra instead treats MIPS `bal 1f` as a branch and starts a block
  at `0x203fc`. That is the remaining MIPS block and edge difference; chain Jaccard and chain edges agree.
- **Literal pools (resolved).** Every decoder says whether an instruction loads from or stores to its data
  reference or only forms it (`lea`, `adr`, ADRP plus ADD, the MIPS, RISC-V, PowerPC and SPARC address pairs,
  s390x `larl`). Memory read or written is a data reference and never a code pointer, even in a literal pool
  inside code; a formed address into code may be one, as may the word an ARM or AArch64 PC-relative literal load
  reads from read-only memory (`ldr r0, =func`). An address a function forms and also loads from is data, as
  `_start`'s `adr r3` to its own pool shows. hello-arm.elf `sub_20338` and `sub_2033c` (`_start`'s literals, which
  happen to decode) are no longer functions, nor is one rampage-only start in hello-thumb.elf.
- **Tail jumps to import thunks (resolved).** PE `jmp [slot]` thunks that follow padding or another thunk are
  functions, so `jmp 0x140028d50` (`fflush`) at hello-x64.exe `0x140001447` is a tail call rather than a block of
  its only caller. ELF PLT and Mach-O stubs were already functions. Unreferenced thunks are now listed too, which
  is why rampage's hello-x64.exe function count rose; Ghidra's export leaves thunks out.
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

1. Resolve the x86-64 switches whose index copy or table base comes from another block (a bounded `r12d` copied
   to `r13`, a table base loaded before a loop). Evidence: eval-ref-x86_64 `0x1008e60`, hello-x64.exe
   `0x140001aca`.
2. Extend AArch64 switch recovery to the bounds it does not yet prove: the inverse form, where `b.ls`/`b.lo` jumps
   to the dispatch and the fall-through is the default, and a `cmp` scheduled away from its conditional branch.
   None of these fixtures needs either.

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
