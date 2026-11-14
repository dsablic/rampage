# Signature corpus reference

The built-in function databases contain hash/name data from declared public-library builds. They recognize
compatible builds; a match does not identify a library version, authenticate source, or establish complete SDK coverage.

## Shipped artifacts

The default databases pass gzip, index and lazy-loading tests and an independent publication audit. They do not
meet the 80% matched-version recall target. The x86-64, AArch64 and i386 counts below are revalidated; the Thumb
database is not rerun.

| Architecture | Masked signature entries | Flywheel PAT rows | Callee keys | Recorded build profiles |
| --- | ---: | ---: | ---: | ---: |
| x86-64 | 11,369 | 7,694 | 822 | 41 |
| AArch64 | 7,037 | 9,188 | 402 | 29 |
| i386 | 2,123 | 0 | 90 | 15 |
| ARM/Thumb | 2,117 | 0 | 0 | 14 |

Thumb also gets the separately built [embedded firmware set](#embedded-firmware-set) for microcontroller
libraries. Counts describe index keys, not unique recognized functions. An index's `signatures` count is the masked entries
plus the PAT rows. The PAT rows are the flywheel's deterministic arms, bundled by `rampage-eval bundle --arm` under
one `flywheel-libid-<arch>` profile each (zlib 1.2.13, LZ4 1.9.4, cJSON 1.7.15, zstd 1.5.4 and Lua 5.4.4 built
with zig cc, clang and Alpine gcc; [flywheel.md](flywheel.md#bundle-a-promotion)). The ARM profiles are Thumb builds. The x64/AArch64
indexes include the frozen musl starter inputs; their original source archive identity is unrecorded and
explicitly unavailable. The other profiles record archive digests, compiler identity, requested optimization,
license declarations, recipe fingerprints and an aggregate measurement witness.

Each architecture has a compressed database and a small provenance index. Metadata listing does not decompress
databases. Database loading is cached separately per architecture and checks the index's digest, lengths, target,
scheme and counts. User databases and data packs retain priority over the built-in corpus.
Upstream notices are retained with source/archive and excerpt digests in the data notice index; they are textual
license declarations, not source authentication or a legal determination.

The promoted Linux profiles cover zlib, LZ4, Lua, SQLite, zstd, mbedTLS and libpng; x64/AArch64 additionally include
the reduced OpenSSL and HTTP-only curl profiles. Several libraries have second versions. x64 also includes the
validated Windows zlib/LZ4 builds and exactly nine GLOBAL functions from MinGW's `pesect.c`; this is not whole-CRT
or Windows DLL implementation coverage. The observed MinGW header identity is 15.0.0 alpha, not an attested release
commit. Broader SDK/runtime coverage is not included.

Two portable x64 profiles cover LLVM compiler-rt 22.1.8's eight original generic C units and glibc 2.40's original
`strverscmp.c` translation unit. Their source archive pins, exact compiler/header/harness identities, finite alias
configuration and dependency receipts are recorded in the
[portable supplement](benchmarks/phase2-1-portable-delivery-2026-10-18.json) and the
[`corpus-x86_64.index.json` provenance index](../crates/rampage-signatures/data/corpus-x86_64.index.json).
The portable supplement keeps all 32 earlier x64 records while adding nine and retiring 58 signature keys through
conservative source-callee-context curation. The SDK/Rust delivery keeps all 34 resulting x64 records exactly, plus
all 27 AArch64 and 14 i386 records, and adds installed musl and Zig compiler runtime on x64, Zig compiler runtime
on AArch64/i386, and Rust std/core 1.87.0 and 1.99.0 on x64. See the
[SDK/Rust delivery evidence](benchmarks/phase2-1-sdk-delivery-2026-10-18.json) for current hashes and raw/curated rows.

For installed SDK profiles, index `archive_sha256` fields identify generated native Zig-cache archives, **not
published upstream source archive pins**. Exact installed source/header inventories are retained; musl's header
reports 1.2.5, but source revisions remain unknown. Rust fields identify verified Linux-musl binary target-component
archives, not rust-src; the owned native rlib identities remain in each recipe. Compiler release strings record
1.87.0 and 1.99.0, not authenticated language-version identification from matched signatures. SDK O2 and Rust O1
are harness labels only; native runtime optimization is not inferred. Zig runtime is not the portable LLVM profile.

## Embedded firmware set

A second bundled ARM database, `data/embedded-thumb.json.gz` (1.31 MB gzip, 2.44 MB JSON; 22,538 masked entries
and 4,189 callee keys over 22 recorded profiles in `embedded-thumb.index.json`), names the library code
microcontroller firmware links: newlib and newlib-nano (libc and libm), libgcc, LLVM compiler-rt builtins,
the FreeRTOS kernel and the STM32F4 HAL/LL drivers. Identification consults it after the ARM corpus for every
Thumb target, ELF or [Cortex-M Raw project](sleigh-decoding.md#cortex-m-profile), as `rampage-builtin`.

| Library | Versions | Built with | Cores and options |
| --- | --- | --- | --- |
| newlib, newlib-nano, libm | 4.3.0, 4.4.0, 4.5.0 | prebuilt in Arm GNU Toolchain 12.3.rel1, 13.3.rel1, 15.2.rel1 | Thumb multilibs v6-m, v7-m, v7e-m, v7e-m+fp hard, v7e-m+dp hard |
| libgcc | GCC 12.3.1, 13.3.1, 15.2.1 | the same toolchains | the same multilibs |
| compiler-rt builtins | LLVM 22.1.8 | clang 22.1.8 | thumbv6m, thumbv7m, thumbv7em, thumbv7em hard float; -O2, -Os, -O3 |
| FreeRTOS kernel (with `heap_4`) | 10.6.2, 11.1.0 | GCC 12.3.1, 13.3.1, 15.2.1 | ARM_CM0, ARM_CM3, ARM_CM4F ports; two configurations; -Os, -O2, -O3, -Og, -O0 |
| STM32F4 HAL/LL, CMSIS core | HAL 1.8.3, cmsis-device-f4 2.6.10, CMSIS 5.9.0 | GCC 12.3.1, 13.3.1, 15.2.1 | Cortex-M4F, STM32F407xx, every module; -Os, -O2, -O3, -Og, -O0 |

It uses hash scheme 3 (`LITERAL_POOL_SCHEME`), which is scheme 2 everywhere except Thumb code:

- A word a PC-relative `LDR` loads from inside the body is hashed as literal-pool data, not decoded as
  instructions. Words below `0x4000_0000` (the Cortex-M code and SRAM regions: pointers to globals, strings and
  functions that move with layout) are masked; peripheral and system addresses, which are fixed per device, are
  kept. The rule does not depend on the image's mapping, so an ELF and a Raw project hash alike.
- BL, B.W and 16-bit B targets are recorded, so a body several functions share is told apart by its callees'
  names, as on x86 and AArch64.
- Trailing `nop` padding is ignored, and the gate needs six instructions (pool words not counted): short
  accessors such as `HAL_GetTick` mask to the same few instructions in every program, so they stay unnamed.
- Each function is hashed over the extents discovery finds in the reference and in a stripped copy of it
  (discovery cannot tell a call to an unnamed `abort` never returns); symbol-size hashes, which span a trailing
  pool no discovered body includes, and exact fallbacks (layout-specific, never matching another link) do not ship.
  Masked hashes two names share stay tombstones.

`tools/embedded-signatures/build.py` fetches the pinned archives (toolchain and source SHA-256s are in the script
and the index), links whole-archive reference ELFs per multilib (with one-instruction stubs for symbols nothing
defines, which the gate never signs) and compiles the sources; `crates/rampage-eval/examples/embedded_signatures.rs`
hashes them. Downloads and build trees stay outside the repository:

```sh
python3 -I tools/embedded-signatures/build.py fetch            # WORK defaults to /private/var/tmp/rampage-embsig-work
python3 -I tools/embedded-signatures/build.py refs             # 255 references from the training toolchains
python3 -I tools/embedded-signatures/build.py compiler-rt      # 12 more with Homebrew llvm@22
cargo build -p rampage-eval --example embedded_signatures --example signature_bundle_index
target/debug/examples/embedded_signatures --output WORK/db.json --gzip WORK/db.json.gz --drop-prefix embsig_ WORK/refs/*.elf
python3 -I tools/embedded-signatures/build.py profiles > WORK/profiles.json
target/debug/examples/signature_bundle_index --database WORK/db.json.gz --profiles WORK/profiles.json \
  --asset embedded-thumb.json.gz --output crates/rampage-signatures/data/embedded-thumb.index.json
```

**Held-out measurement.** Arm GNU Toolchain 14.3.rel1 (GCC 14.3.1, newlib 4.5.0 as that release built it) is not
used for training. `build.py fixture` builds two owned FreeRTOS applications with it
(`tests/fixtures/firmware/embedded-libs/`): Cortex-M4F at -Os with newlib-nano, libm, libgcc soft double and the
STM32F4 HAL, and Cortex-M0 at -O1 (an optimisation level not trained either) with full newlib and soft float. Both
use a FreeRTOS configuration unlike the two training ones. The committed stripped ELFs and their flash images are
scored against the library functions of the symbolized builds (`--library` the 14.3 references, `--program` the
fixture's own objects), so any name on the fixture's own code counts as spurious:

| Fixture | Library functions | Correct | Wrong or spurious | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| `embedded-libs-m4f` (ELF) | 158 | 80 | 0 | 100% | 50.6% |
| `embedded-libs-m4f` (Raw, vector table) | 158 | 81 | 0 | 100% | 51.3% |
| `embedded-libs-m0` (ELF) | 227 | 70 | 0 | 100% | 30.8% |
| `embedded-libs-m0` (Raw, vector table) | 227 | 71 | 0 | 100% | 31.3% |

The `libid-embedded-m4f` and `libid-embedded-m0` slices of `tests/fixtures/data/eval-manifest.json` gate these
numbers; the fixtures also join the toolid truth as `arm-none-eabi-gcc` builds. Misses are mostly code a
different GCC generated differently (newlib's C, FreeRTOS), kernel functions whose layout depends on the
FreeRTOS configuration, bodies below the gate, functions discovery does not reach (handlers only the vector table
names, unused weak callbacks) and collisions without named callees (`_close_r` and friends call libnosys stubs
that are all alike). With the newest toolchain held out instead (training 12.3, 13.3 and 14.3, firmware built
with 15.2) recall is 36.7% (M4F) and 15.0% (M0), still with no wrong or spurious name. compiler-rt built by clang
23.1.5 (held out) is recognised at 100% precision and 65–68% recall per core. The same toolchain's own build is
recognised far better: newlib and libgcc archive code is byte-identical within a toolchain release.

Limits: one HAL family (STM32F4), GCC-built newlib and FreeRTOS only (no IAR, Keil/armcc, picolibc or vendor
SDKs), little-endian Thumb only, and FreeRTOS signatures match only configurations whose struct layouts agree
with a trained one. A firmware's own copy of a library function with identical code is named after the library.

## Recognition policy

Corpus composition uses collision-safe union, not priority overlay. Full named training references supply negative
collision evidence without exporting their runtime, local or harness names. A global image-hash split rejects
training references that are also held-out targets anywhere in the aggregate.
The exact frozen musl inputs are a separately reported legacy exception: their original source-image provenance
is unavailable, so their inclusion does not earn a complete historical training-provenance attestation.

Promoted corpora withhold raw exact fallback answers. Such keys can accidentally coincide across different linked
layouts, even when their masked bodies are already ambiguous. Masked and callee-qualified answers remain available;
withholding does not affect the generic matcher, hash schemes or explicitly supplied user databases. Withholding creates
persistent tombstones for known keys. Composition that introduces new keys requires applying the curation policy again.

The shipped corpus accounts for **95 cases: 39 x64 + 27 AArch64 + 15 i386 revalidated, and 14 Thumb not rerun**.
The 81 revalidated cases have zero owned/full wrong or spurious names after reloading the exact three exports.
Raw recall gates fail in 16 x64, 13 AArch64 and five i386 cases. All four Rust
profiles are included despite low recall; the raw evidence retains std 1.87's original one-wrong result.
Generic source-reference conflict rejection and exact-fallback withholding remove unsafe answers, not per-name
blacklists or gold deletion. PE truth uses checked PDB procedure ranges, not guessed PUBLIC-name sizes.
This is bounded corpus evidence, not a universal precision guarantee.
Per-library and aggregate recall failures remain recorded. Low recall against the 80% matched-version target does
not block shipping precision-checked databases, and does not replace the precision checks for default artifacts.

Identification reports names, and the evaluator compares them, without the build-local counters Zig numbers its
generated declarations with: `math.ldexp.ldexp__func_40` and `c.stdlib.qsort__struct_61.wrap` are
`math.ldexp.ldexp__func` and `c.stdlib.qsort__struct.wrap`. Zig 0.17.0 and 0.17.1 give the same instance
different counters. Instances of one generic declaration then share a name. Applying signatures names the later instances `name@2`,
`name@3` in address order. The databases keep the spellings they were built with, since their callee keys hash
them. A callee named by a flywheel row, which is canonical, therefore does not complete a bundled callee key built
over a counted spelling. The collector's per-body diagnostics pass canonical proposals as callee labels in the
same way.

The bundled call graph (`data/callgraph.json.gz`) is separate from the signature databases. It holds training call
sequences from the flywheel corpus (callee names in call-site order, per architecture and caller) and names the
callees of functions the databases named. It is generated and gated by `rampage-eval bundle --call-graph`
([flywheel](flywheel.md#bundle-a-promotion)).

Strict canonical-name behavior is the default. Explicit `--producer-alias-sets` enables the revalidated aggregates'
`elf-producer-alias-sets-v3` policy: full-target grading accepts only verified exact native ELF same-range aliases;
reference admission requires a unique default-visible strong definition with only weak default-visible aliases.
Original source-canonical and selected-definition callee contexts remain separate from answer labels. Original
strict owned gold and raw proposals are preserved; the policy does not change PE/PDB alias handling, generic
matching, hash schemes or thresholds. Alias metadata is neither publisher authentication nor runtime object identity.
The strict policy's alias refusal and the v1 policy's glibc 0/1 remain frozen records; v3's actual 1/1 is separate
producer-backed evidence.

Requested O1/O2 variants can produce identical signature databases and stripped images. Those cases remain separate
measurements but do not establish independent optimizer diversity. Bare compiler flags are not evidence of a
prebuilt runtime library's optimization level.

## Producers

`tools/signature-corpus.py` consumes an explicit offline cache of pinned source archives. It checks and extracts the
same bounded regular-file snapshot, records actual commands and artifacts, freezes evaluator/collector executables,
and never runs generated target programs. Configured host scripts run with a clean recorded environment and isolated
home directory. Supported host build tools still execute; this is not an arbitrary-source execution sandbox.

```sh
python3 tools/signature-corpus.py --list
python3 tools/signature-corpus.py \
  --only libpng-1.6.44 --target aarch64-linux-musl --optimization O1 \
  --source-cache "$SOURCE_CACHE" \
  --output-dir target/signature-corpus/libpng-aarch64 \
  --eval target/debug/rampage-eval \
  --builder target/debug/examples/signature_corpus
```

The default ownership cohort consists of externally visible strong ELF definitions or public executable COFF
definitions with checked global PDB procedure ranges. Local/hidden/weak functions are excluded before scoring.
PE production requires separate explicit identity-matched PDBs for both programs and recorded native linker replay
with GC/ICF disabled. Public PDB aliases are not a substitute for sized producer procedure records.

`tools/signature_portable.py` supplies the two finite source profiles through the pinned
[`portable-compiler-rt-fragment.json`](../tests/fixtures/signatures/portable-compiler-rt-fragment.json) and
[`portable-glibc-fragment.json`](../tests/fixtures/signatures/portable-glibc-fragment.json) recipes. Host Clang
22.1.8 compiles original C at O2 for `x86_64-unknown-linux-musl`, freestanding with no CRT; targets are never run.
LLVM's eight-unit subset is not Zig runtime or whole builtins coverage. glibc owns only strong `__strverscmp`;
the weak `strverscmp` alias is retained, not counted as a second owned function. Its finite standalone alias
configuration and exact target-header bytes are pinned, but the Zig-vendored musl header revision is unknown.
This does not establish native configured glibc, distribution libc.a or full native ABI coverage. Complete upstream
legal texts and their source/archive/copied digests are retained in the
[`notices/index.json` notice index](../crates/rampage-signatures/data/notices/index.json).

The installed-runtime producer offers a separate explicit ELF linked-artifact scope. It binds archive members and
actual kept linker-map inputs to raw names, producer ranges and instruction bytes, allowing only supported native
relocation bits to differ. Unsupported relocations, ambiguous ownership and empty truth refuse the scope. This is
not source authentication or general object/archive project loading.

Rust target components can be materialized as data under the ignored target directory without executing installers.
Their archive snapshots, expanded metadata, selected file membership and materialized file hashes are bounded and
checked; receipt file hashes alone do not establish archive membership.

SDK/Rust measured outputs use a clean recorded environment, frozen native input snapshots and explicit native
linker replay with GC/ICF disabled. Only selected component members supply owned signature inputs; unselected
archives and dependency objects do not. Rust metadata members are not native code, but their original archive
ordinals remain part of member identity. Source hashes and native snapshots do not independently reproduce a build.
Complete installed public musl/Zig, related LLVM and Rust MIT/Apache/library notices are retained byte-for-byte;
the two Rust library HTML notices preserve declared upstream trailing-whitespace exceptions without normalization.

Eight technical refusals stay quarantined in the
[SDK disposition](benchmarks/phase2-1-sdk-disposition-2026-10-18.json): AArch64 musl, x64/AArch64 libc++, libc++abi
and libunwind, and Thumb compiler runtime. Their native relocation/capture limits are not recall failures or shipped
coverage. Provisional C++ results and all raw failed attempts are kept separately; the delivery attempts no further
LLVM repairs.

The `tools/gen-signatures.sh` wrapper accepts the same corpus arguments. `ZIG`, `RAMPAGE_EVAL` and
`RAMPAGE_SIGNATURE_CORPUS` select existing producer executables; `--only`, `--target` and `--optimization` are
repeatable. A native tool build is available with:

```sh
cargo build --locked -j 2 -p rampage-eval --bin rampage-eval --example signature_corpus
tools/gen-signatures.sh --list
```

| Producer output | Contents |
| --- | --- |
| `inventory.json` | Profiles, outcomes, commands, source/tool/artifact identities and measurements |
| `builder-report.json` | Owned truth, baseline/after metrics, disagreements and the original gate result |
| `db.json`, `db.json.gz` | The same ordered database as JSON and deterministic gzip |
| `truth.json` | Original library-owned truth, not a newly filtered denominator |

The original gate requires at least 80% recall and zero wrong/spurious names. Failed gates retain their
measurements as `measured_failed` and return failure; unsupported targets are not successful coverage.

SQLite's public-domain amalgamation profile disables thread safety and extension loading. Its license-containing
source file is hashed in full; the distributed notice is a verbatim disclaimer excerpt rather than the amalgamation.
zstd extracts only declared library/license roots and does not follow unrelated test symlinks; global path, byte
and entry checks still cover the archive. mbedTLS uses its unmodified default configuration, including library
self-tests, not a claim about typical production configurations. libpng uses the unchanged prebuilt configuration
header with SIMD options disabled and a separately owned, fixed zlib dependency that is excluded from PNG truth.

## Aggregate validation

`signature_aggregate` requires hash-bound case reports and their stripped/symbolized twins. Repeated images may
share a digest, but every case and every supplied input identity remains accounted for. All named proposals are
graded against full twin truth, not only addresses owned by the library under test.

Default-corpus validation additionally supplies every original training reference and enables raw-exact withholding:

```sh
target/debug/examples/signature_aggregate \
  --database "$DATABASE" --case "$CASE_REPORT" \
  --target "$STRIPPED_TARGET" --symbolized "$SYMBOLIZED_TARGET" \
  --reference "$TRAINING_REFERENCE" --withhold-exact-fallbacks \
  --output target/candidate.json.gz --report target/candidate-report.json
```

Reports distinguish reference-conflict removals from raw exact fallback removals. Forward, reverse and rotated
input orders must produce identical compressed output. A nonzero recall-gate exit retains the artifact and all case
measurements; it does not authorize promotion when wrong/spurious proposals remain.
PE aggregate cases additionally require the actual reference image and explicit `--pdb` inputs for both paired
producer PDBs. Every nonlegacy database must be associated with a validated case; only the two exact frozen musl
digests are admitted as separately disclosed legacy inputs without original case provenance.

The builder's optional `--diagnostic-limit` (0–512, default 0) emits bounded, address-sorted symbol/discovery evidence.
It preserves actual gates, ambiguity tombstones and missing-callee evidence, counts omitted rows, and keeps supplied
reference labels separate from final target proposals. Diagnostics do not change matches or establish execution,
complete function boundaries or semantic identity. Case reports lacking the shared-validator source hash are
not accepted as current aggregate evidence.

The no-argument starter generator rebuilds musl JSON/gzip/count inputs. It does not rebuild the composed default
corpora; deliberately changing those frozen legacy inputs requires a separately reviewed baseline update.
Ordinary user/pack database inputs remain JSON. FLIRT/FIDBF import, near-miss matching and authorization to publish
signatures derived from private binaries are outside this corpus pipeline.

Generated native programs, PDBs, archives and runtime captures are evaluation inputs, not bundled outputs. Only
reviewed hash/name databases and their provenance data belong in the default signature assets. Raw attempts and
frozen baseline reports are never overwritten by a new consumer replay or acceptance decision.

Broader SDK coverage and the recall target are not claimed. User-supplied
[PAT and FunctionID inputs](signature-imports.md) and [fuzzy candidates](fuzzy-signatures.md) are documented
separately.
