# Bounded C++ virtual corpus

This reference describes the owned six-method comparison lane, its fixture oracle and its JSON evidence. It is
separate from the [checked layout-import contract](debug-layout-import.md). The recorded local acceptance below
covers both owned variants against installed Ghidra 12.1.4. It is not speed parity, general semantic equivalence or
general C++ decompilation acceptance.

## Components and inputs

| Component | Contract |
| --- | --- |
| `tests/fixtures/debug-cpp-virtuals/build.sh` | Builds owned ELF fixtures and checks compiler/source facts |
| `tests/fixtures/debug-cpp-virtuals/oracle.json` | Expected layout, method access/arithmetic and raw table words |
| `tests/fixtures/debug-cpp-virtuals/verify_virtual_oracle.py` | Checks source constants, compiler dumps and ELF facts |
| `tools/ci/debug-cpp-virtual-oracle.sh` | Generates fixtures; `--check` runs a command within their lifetime |
| `tools/ci/debug-cpp-virtual-acceptance.sh` | Runs local loader/API/worker/UI tests within the owned fixture lifetime |
| `tools/cpp_virtual_corpus.py` | Controls native/reference inputs, separate CLI integration and bounded report output |
| `tools/ghidra_cpp_virtual_export.java` | Installed-Ghidra readback/export adapter; not a target program |

The fixture recipe uses freestanding C++17, `-fno-exceptions`, `-fno-rtti`, fixed-address x86-64 little-endian ELF64
and no system libraries. It generates `dwarf4-o1` (DWARF 4, `-O1`) and `dwarf5-o2` (DWARF 5, `-O2`) variants.
Neither generation nor comparison executes a fixture. Compiler record/vtable dumps are mandatory oracle inputs,
not optional diagnostic logs. The recipe records normalized commands, tool versions, source/dependency hashes and
artifact hashes; generated binaries live only for its owned scratch lifetime.

The positive `records` group selects the actual out-of-line methods of two distinct records, not wrapper functions:

| Record | Method | Independent expression | Declared virtual slot |
| --- | --- | --- | --- |
| `VirtualRecord` | `readCount()` | Return signed `count` | 0 |
| `VirtualRecord` | `writeCount(int replacement)` | Store `replacement` to `count` | 1 |
| `VirtualRecord` | `readTail()` | Return unsigned promotion of `tail` | None; nonvirtual |
| `PeerRecord` | `readCount()` | Return signed `count + 17` | 0 |
| `PeerRecord` | `writeCount(int replacement)` | Store `replacement - 3` to `count` | 1 |
| `PeerRecord` | `readTail()` | Return unsigned promotion of `tail`, plus 1 | None; nonvirtual |

Each record is 16 bytes with explicit alignment 8: opaque vptr storage at offset 0, four-byte signed `count` at
offset 8 and one-byte unsigned `tail` at offset 12. Source-visible constants measure the record and data fields.
The artificial vptr has no source `offsetof`: its offset comes from Clang's AST record dump, with width checked
against IRgen pointer storage and source `sizeof(void *)`. The producer loader must separately establish the exact
artificial-member graph, same-CU identities and method proof. Reused method names do not merge the records.

The fixture set also contains `missing-alignment`, `lookalikes`, `inherited` and `signatures` groups, plus
symbols-only ELF controls. These exercise absent explicit alignment, ordinary callback/pointer-chain fields,
inheritance/secondary tables/this-adjusting thunks, const object pointers, references, by-value calls and virtual
destructors. The initial comparison selects none of these negative groups; their report status is `not_selected`.
Production compiled-loader acceptance covers these refusal cases separately. Their existence is not comparison
coverage or evidence that the live reference lane has exercised them.

## Explicit local invocation

Required tools are already-installed Clang with the fixture's record/vtable dump format, an ELF-capable linker and
objcopy, Python 3.10+, Bash and a SHA-256 utility. Comparison additionally requires explicit Rampage CLI and
protocol-4 worker executables, installed Ghidra 12.1.4 and JDK 21. The tools do not install dependencies, Rust,
Ghidra, a JDK or any target runtime. Ghidra must supply matching bundled processor/specification bytes.

Example tool selection uses generic paths; replace them with explicit installed executables and an existing owned
temporary parent:

```sh
export PYTHON=/opt/python/bin/python3.10
export CLANG=/opt/llvm/bin/clang
export LD=/opt/llvm/bin/ld.lld
export OBJCOPY=/opt/llvm/bin/llvm-objcopy
export TMPDIR=/path/to/existing/owned-temporary-parent

bash tools/ci/debug-cpp-virtual-oracle.sh
```

If an existing Rust toolchain supplies LLVM tools instead, `RUST_SYSROOT` and `RUST_HOST` select
`lib/rustlib/$RUST_HOST/bin/rust-lld` and `rust-objcopy`. Set those two variables and leave `LD`/`OBJCOPY` unset, or
provide explicit overrides. This selects existing files; it does not invoke a Rust installation. `CLANG`, `PYTHON`
and the temporary parent remain explicit inputs. On macOS, the recipe handles those tools' existing sysroot library
location.

The wrapper accepts `--check command [arguments...]`. It still performs generation and oracle checking first, then
exports `RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES` and `RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE` for the command. It removes its
scratch tree when the command exits. Use the wrapper rather than retaining paths to an earlier generation:

```sh
bash tools/ci/debug-cpp-virtual-oracle.sh --check \
  "$PYTHON" -B tools/cpp_virtual_corpus.py \
  --rampage /path/to/rampage \
  --worker /path/to/rampage-worker \
  --ghidra-headless /path/to/ghidra/support/analyzeHeadless \
  --java-home /path/to/jdk-21 \
  --variant dwarf5-o2 \
  --timeout 120 \
  --output "$TMPDIR/cpp-virtual-dwarf5-o2.json"
```

`--variant` accepts `dwarf4-o1` or `dwarf5-o2` and defaults to `dwarf5-o2`. One invocation compares six methods in
one selected variant; selecting both requires separate invocations and distinct report paths. `--timeout` is a
finite, positive tool-startup-inclusive deadline per subprocess, default 120 seconds and at most 600. The reference
adapter additionally bounds each inner decompile to 1–30 seconds. `--output` creates a new report file and refuses
to overwrite one; without it, the runner prints JSON to stdout. Wrapper provenance also uses stdout, so an explicit
report file keeps the JSON separate. Exit status is zero only when the report's whole-lane success gate passes.

No GitHub Actions dispatch is part of this lane. Automatic CI builds are limited to pushes of version tags such as
`v1.2.3` or `v1.2.3-rc.1`; manual dispatch remains available. Ordinary branch pushes and pull requests do not build.
This local lane creates no release tag and dispatches no workflow.

## Controlled backend protocol

The comparison has two distinct tracks:

1. **Controlled backend comparison.** A checked CLI preview supplies accepted consumer layout descriptors and exact
   method prototypes. Native protocol-4 requests and the Java adapter receive those same inputs, exact method VAs,
   symbols and compiler context. The native worker processes each selected method in a fresh process; the Java
   adapter decompiles all six selected methods in one fresh headless batch.
2. **Separate CLI round trip.** A fresh CLI apply uses the complete reviewed fingerprint on an owned image copy.
   Subsequent fresh inline-native CLI decompiles reopen accepted annotations and check the actual methods
   independently. This track does not use `--isolated` and is not substituted for controlled protocol-4 output.
   Production worker/native parity is exercised separately by the virtual acceptance tests.

The CLI can automatically select a configured or sibling worker. This lane therefore removes `RAMPAGE_WORKER`
and executes a byte-identical, hash-checked CLI copy in a private directory with no sibling worker. The original
explicit worker executable remains the controlled protocol-4 backend; no installed executable or runtime is changed.

The runner independently reads ELF `PT_LOAD` ranges. Both backends receive the same backed bytes, initialized zero
tails, exact gaps and R/W/X permissions; no broad synthetic executable mapping replaces them. The Java adapter
disables auto-analysis, removes imported enrichment, rebuilds controlled memory and reads back its bytes, ranges,
gaps and permissions against the memory digest. It installs only the two admitted flat consumer records and the
selected explicit-`self` prototypes. Layout readback checks field offsets, widths, signedness, alignments and opaque
`void *` storage rather than accepting undefined bytes, an integer substitute or a callback field.

The language is `x86:LE:64:default` with compiler `gcc` (`x86:LE:64:default:gcc` in native results). Both sides require
the GCC/SysV default model, whose specification name is `__stdcall`; that label is not a Windows ABI claim.
Data organization is pointer 8, int 4, long 8, with scalar alignment entries 1, 2, 4 and 8. `self` is an explicit
record-pointer parameter, never an injected C++ `this`. Actual parameter widths, record identity, semantic types
and register-storage descriptors must agree. Native return storage is unavailable and is not claimed matched.

| Effective setting | Required value |
| --- | --- |
| Read-only constant propagation (`respect_readonly`) | `false` |
| Prototype evaluation (`protoeval`) | `default` |
| Maximum instructions | 100,000 |
| Maximum jump-table entries | 1,024 |
| Simplification | `decompile` |
| C output / syntax tree | Both enabled |
| Reference auto-analysis | Disabled |

Specification identity includes the bundled manifest and SHA-256 of the actual `x86-64.sla`, `x86-64.pspec` and
`x86-64-gcc.cspec` files used by installed Ghidra. The runner also records CLI, worker and headless-launcher hashes,
source/oracle identity, controlled memory identity and input/request hashes. Missing results, missing effective
settings, unavailable required parameter storage, unexpected enrichment or identity disagreement fail closed;
success is not inferred from similar-looking text or a successful process exit alone.

## Oracle and evidence limits

Each backend is checked against the independent source/oracle before agreement is accepted. The checks require the
right return kind/width, actual parameter types/storage and the intended field access or store and arithmetic.
`PeerRecord`'s `+17`, `-3` and `+1` distinguish same-named methods that otherwise share the same layout. Agreement
between two incorrect outputs is not the acceptance criterion.

Expression evidence is deliberately narrow: the parser recognizes a rendered linear expression over one named
field or parameter plus bounded constants, modulo 2^32, with restricted safe casts/promotions. Reads must have one
return expression; writes must have exactly one `count` store and at most a void return. Additional control flow,
side effects, unsupported casts/tokens or unavailable evidence refuse the case. This is not P-code equivalence,
general C semantic analysis, a decompiler-quality score or proof over arbitrary signed-overflow behavior. Exported
high-P-code call diagnostics do not change the expression metric's scope.

Raw table-word checking is another separate oracle. The owned `-fno-rtti` tables have two raw zero words followed
by the exact `readCount` and `writeCount` method symbols. The runner checks these words independently of backend
agreement. Production review links additionally require the exact producer method proof, declared slot index and
discovered entry after source-only native validation. Neither layer establishes a table owner or an arbitrary
object's vptr. The prefix stays `UnverifiedPrefix`, with unknown offset-to-top and the raw words retained; it is not
upgraded to known RTTI by the oracle or a source-method link.

The `debug_virtual_*` and `debug_peer_*` wrapper functions are not selected. Their virtual indirect calls are not
resolved by these source links and remain separate from raw-table/producer association evidence. No resolved
`CALLIND`, typed virtual dispatch, inheritance/thunk reconstruction or broad C++ ABI recovery is earned by this
six-method lane. There is no IDA/ILSpy lane, commercial corpus, broad-binary coverage or earned performance claim.

## Report schemas and interpretation

| Schema tag | Role |
| --- | --- |
| `rampage-cpp-virtual-input-v1` | Controlled Java-adapter request, bound by `input_sha256` |
| `rampage-cpp-virtual-reference-v1` | Actual installed-Ghidra readback and per-method exports |
| `rampage-cpp-virtual-corpus-v1` | Whole comparison, CLI integration, process metadata and coverage report |

The input binds mappings, accepted layouts/declarations, native-equivalent operations, selected methods,
specifications and options. The reference export includes actual language/compiler/version/settings, memory and
layout readback, per-method code/signature/storage evidence, warnings and errors. A missing selected method remains
a failure, not a silently reduced reference set.

The corpus report retains `cases`, `warnings`, process evidence, accepted consumer inputs and available native,
reference and integration responses. `metrics.counts` distinguishes `selected`, `admitted`, `native_success`,
`reference_success`, `settings_matched`, `native_oracle_match`, `reference_oracle_match`, `agreement`,
`integration_success` and `refusals`. Transport/decompile success alone is not an oracle match. Partial or failed
cases remain in the six-case `denominator`; gate failures also retain selected-case entries. Warnings are retained
and counted by category rather than hidden by successful output. The top-level `ok` requires agreement and no
recorded failures for every selected case, including the separate integration checks.

### Timing and memory

Process wall times include tool startup and supervision. Native per-method cold processes, a Java cold batch, Java
inner-decompile timings, fixture generation, preview/apply and CLI integration have different scopes. “Cold” means
a fresh process, not a cold filesystem cache. These measurements are diagnostic only: do not divide their timings
into a speed ratio or infer parity from the report.

RSS uses the maximum observed **sum of supported process-group RSS samples**, not private memory, a guaranteed peak
or a continuous measurement. Shared pages can be counted more than once. Reports retain sampling interval, sample
count, source, errors and availability. No observation means unavailable, not zero memory use; absent sampling
cannot support a resource-success claim. Subprocess supervision, bounded capture and owned-scratch handling are
runner safeguards, not an operating-system sandbox or a hard-memory-peak guarantee.

The supervisor owns one process group through a held, unreaped direct guardian child. Tool and sampler processes
inherit that group. Cleanup never treats a sampled descendant PID or timestamp as authority to signal it. Tools
that detach into other groups are unsupported; an observed escape fails the operation rather than claiming it was
cleaned up. This is why the CLI track uses inline native decompilation. The actual standalone protocol-4 worker and
the installed Ghidra launcher/decompiler chain remain the controlled backends.

The tool deadline covers pre-exec/startup, runtime and bounded capture after guardian registration. OS fork,
scheduling and unkillable kernel waits are not real-time bounded. Environment controls remove inherited Java option
injection and select scratch-owned application directories; the Java adapter checks the actual settings/cache/temp
locations. Those checks do not authenticate replacement executables or create a filesystem sandbox.

## Recorded local acceptance

The x86-64 ELF fixtures were produced by Apple Clang 21.0.0 (`clang-2100.3.34.2`). The actual reference backend was
Ghidra 12.1.4 with OpenJDK 21.0.12.1. Native binaries use the bounded development profile; no release API, UI or
whole-workspace performance build was made. Both variants completed in one externally capped local gate in
37.3 seconds including fixture generation. Neither ELF target was executed.

| Variant | Admitted | Native oracle | Ghidra oracle | Settings/storage | CLI reopen | Validated agreement |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `dwarf4-o1` | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 |
| `dwarf5-o2` | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 |

Both runs independently matched the exact raw vtable words. Memory ranges/bytes/permissions, layout offsets,
opaque `void *` storage, processor/compiler settings and actual scratch directories passed readback. Prefix status
remained `UnverifiedPrefix`; no offset-to-top, object-vptr, table-owner or resolved indirect-call fact was added.
Negative groups remained explicitly unselected by this comparison, not counted as differential successes.

These observed resource values have different scopes and do not form a speed or memory-quality ratio:

| Variant | Runner wall, s | Native cold case, s | Java cold batch, s | Native observed MiB | Java observed MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `dwarf4-o1` | 17.166 | 0.401–0.427 | 5.304 | 38.0–39.9 | 427.6 |
| `dwarf5-o2` | 17.129 | 0.409–0.465 | 5.183 | 37.6–40.2 | 511.9 |

Each native case had four RSS observations, except one DWARF-5 case with five. The Java batches had 56 and 55
observations respectively; guardian and sampler memory was excluded. The retained receipt categories per variant
were `consumer_checked: 13`, `consumer_producer: 13` and `additional_consumer_evidence: 18`. The first two include
duplicate checked/raw views; the last is supplemental review content, not 18 engine warnings. No warning category
was silently discarded to earn the case results.

Selected identities from the accepted runs are retained below. CLI-copy bytes matched the original CLI hash.
Raw exports, local paths, application projects and generated binaries were removed rather than committed.

```text
cli_sha256=afbba29856d4ae461a07a60b85f26eb32bff4d36cc88d2e4c9817daeb00ff53a
worker_sha256=4ca81e879df5e713be9d46a8a97b5f59fa79b435588e63034cfa8a2497993259
headless_launcher_sha256=302880328a0024ee24cfe0326d4d9a61c2237116d95f2e0e0df090f747f95e30
compiler_bundle_sha256=b88c9e33438bfe392052fa47461123ce5c2fdd588b93b38b60aa9d694207f854
oracle_sha256=65cdedf907cb5e67e9353cde861459818f695616373350d9c4328a356e1c8fde
source_cpp_sha256=bc9485e86c37faa86d51a82e42328a0efc3507bb3c4b47d280816d6b48d55bdb
dwarf4_o1_image_sha256=6d2392c6fae201f77d6b3ee203cbc30b5f25f77c043f6bc5a00fb6ae04527f46
dwarf4_o1_memory_sha256=1d646a4f90ce9ce7685526aadbfa0a1b476a46050983419c5de72841b0fb28f8
dwarf4_o1_input_sha256=4ed12b1fc36ae961ab3832a82345db0a6b5158ce7225e349f9ecf8b2ad246b0d
dwarf5_o2_image_sha256=7bc44950cb8d888e81d2633d00a5936a2af28399ea6780a2a177cc52eec65ccd
dwarf5_o2_memory_sha256=9167a8161264c9f29e59c53037292a81f0c260e4d7f296b4908f9b8b737676f3
dwarf5_o2_input_sha256=70ab9f9df419e23948806d776e4cde0da3ceee381ec1755fdc7d50729eb24f61
```

## Budgets and operational boundary

| Boundary | Limit |
| --- | --- |
| ELF image / aggregate mapped memory | 1 MiB each |
| Selected methods / independent method bound | 6 / 128 |
| Selected method symbol extent | 128 bytes |
| Aggregate rendered text / parsed text per method | 1 MiB / 8 KiB |
| Captured stdout / stderr per process | At most 1 MiB / 64 KiB; some requests use smaller stdout caps |
| JSON input/export | 4 MiB |
| Per-process deadline / reference inner deadline | At most 600 seconds / 30 seconds |
| Production virtual review | 32 named tables, 64 slots/table, 256 links, 128 KiB text |

The runner uses fresh owned scratch and bounded image/text/process inputs. Review/apply writes only its owned
image's annotation sidecar, not analyst projects or target bytes. Inputs and reports are local; no target execution,
debugger attachment, provider submission, package installation, private/commercial binary ingestion or runtime
linkage is required. Environment/supervision controls do not authenticate replacement executables or eliminate
filesystem races. Reports can include local command/specification paths and stderr: review and redact them before
sharing; do not put credentials or private host paths in public examples or publish raw reports unreviewed.
