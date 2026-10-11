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
